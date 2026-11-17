The PIC backend imports the full compiled constructor metadata of Ghidra 12.1.2,
pinned to source commit `42db038f3c88c6bd7e9bedbb919138111f8b77fd`.
`data/upstream` retains the original PIC SLEIGH descriptions; `data/constructors.json`
is an unabridged machine-readable export of all 13 compiled languages. The
exporter reads constructor decision masks, operand expressions, register/name
attachments, print pieces, token offsets, and indirect-flow p-code metadata.
`Parse(nil, architecture)` uses that export; a reader accepts the same exported
schema. Apache-2.0 and upstream notices accompany both the package and generated
standalone Rust crates. Runtime code has no Ghidra, Java, or other dependencies.

| Stream | Source profiles | Imported forms | Physical frames |
|---|---|---:|---|
| `pic12` | `pic12`, `pic16c5x` | 222 | 2 bytes, 12 significant bits |
| `pic14` | `pic14`, `pic14-enhanced` | 290 | 2 bytes, 14 significant bits; optional 4-byte macro aliases |
| `pic17` | `pic17` | 559 | 2 bytes, 16 significant bits |
| `pic18` | `pic18`, `pic18-extended` | 2,918 | 2 or 4 bytes |
| `pic24` | `pic24e`, `pic24f`, `pic24h` | 7,545 | 4 or 8 bytes, 24-bit words plus phantom bytes |
| `dspic` | `dspic30f`, `dspic33f`, `dspic33e`, `dspic33c` | 12,073 | 4 or 8 bytes, 24-bit words plus phantom bytes |

The total is 23,607 fixed-mask forms. Literal SLEIGH subtables become structured
finite name tables, so independent DSP prefetch choices do not require millions
of duplicated instruction records. Register classes/pairs, DSP operand groups,
file registers, indirect pre/post addressing, literal values, split long targets,
and signed relative fields retain their source definitions. The source-defined
PIC14 `BC`/`BZ`/`BNC`/`BNZ` two-instruction aliases require the `*-macros` profiles.
PIC18 extended operations require `pic18-extended` (`pic18-xinst`). `pic16` is
accepted as an alias for the historical 16-bit instruction stream, `pic17`;
Microchip PIC16 device-name families normally use the `pic14` stream instead.
Each named source profile can also be passed directly as the architecture.

Addresses in the public Go and Rust APIs are **physical byte offsets**. A
baseline/midrange instruction advances two bytes; a PIC24/dsPIC instruction
advances four bytes. Thus a PIC24 hardware PC of 2 corresponds to byte offset 4
in the input stream. Branch displacement units and long absolute fields are
converted accordingly. Data-memory operand addresses retain byte units.
`TargetWithPage` / Rust `target_with_page` resolve cross-page PIC12/PIC14 and
PIC17 `LCALL` targets from a caller-supplied page latch. Without latch context,
the shared target formatter/assembler uses the current code page. Banked file
operands retain the source's banked syntax; the codec does not simulate changes
to bank, page, repeat, or skip state across a running program. Device-specific
SFR maps are the maps in the selected upstream language, not a database of all
individual Microchip device peripherals.

Ignored instruction bits and container padding use optional structured operands.
Decode followed by exact encode preserves every accepted byte, including nonzero
PIC24 phantom bytes. Text omits these fields and normalizes them to zero. Phantom
bytes preserved from a file are container data; actual hardware phantom reads
return zero. Malformed/truncated frames, invalid register attachments, PIC18
continuation markers, and architecturally forbidden move destinations are
rejected. No CPU execution, cycle accuracy, verifier, or peripheral emulation is
claimed. PIC/dsPIC variants absent from these 13 source languages, including new
instruction streams such as dsPIC33A, are outside this corpus.

Several upstream distinctions are resolved explicitly:

- Transparent SLEIGH context/skip/repeat wrappers have no extra instruction bytes.
  The synthetic PIC17 `BADCALL` sentinel is omitted; its bytes use real `CALL`.
- Two PIC18 semantic constructors write forbidden `MOVFF`/`MOVSF` destination
  PCL. They are reported as rejected source records, along with the sentinel.
  Numeric and named destination forms also reject PCL and TOSL/TOSH/TOSU.
- PIC18 long CALL/GOTO/LFSR require their documented continuation qualifiers,
  which some upstream patterns leave unconstrained.
- Classic midrange MOVLW/RETLW/ADDLW/SUBLW alias masks and the enhanced MOVLB/NOP
  overlap follow hardware encodings. ADDWFC/ASRF/CALLW/RESET/SUBWFB present in
  Ghidra's classic source are enabled under the enhanced profile.
- Legacy PIC18 PUSHL uses `0xEAkk`; upstream SLEIGH uses `0xFAkk`. The correction
  follows Microchip DS39762F page420 and independent gputils. The retained Ghidra
  vector records the original source bytes separately.

The address-container convention follows Microchip's
[PIC24F Flash Program Memory reference](https://ww1.microchip.com/downloads/aemDocuments/documents/OTH/ProductDocuments/ReferenceManuals/30009715d.pdf).
The PUSHL correction and traditional extended opcodes are specified in the
[PIC18F97J60 datasheet](https://ww1.microchip.com/downloads/en/devicedoc/39762f.pdf).
Newer PIC18 device families can use different extended encodings and are not
implied by this legacy PIC18 profile.

Validation uses every imported form, not a hand-selected opcode fixture. The
retained Ghidra corpus covers 23,607 representative forms with matching source
frame lengths: 23,180 exact assembler matches, 421 alternate assembler selections,
and six Ghidra backfill failures (long CALL/GOTO/LFSR). The one PUSHL source-byte
correction is explicit. The independent gputils1.5.2 corpus covers 3,989 small-core
forms: 3,988 exact byte matches and one normalized enhanced NOP alias. Four rows
are emitted as data by gpdasm rather than recognized instructions (CLRW aliases,
a device-dependent six-bit MOVLB, and the continuation NOP). Extended MOVSF/MOVSS
brackets and ADDULNK/SUBULNK are normalized from gpdasm's printed syntax for gpasm.
These are tool limitations, not independent instruction-assembly coverage.

`go test ./pkg/pic` checks complete source-constructor accounting, retained oracle
bytes, every form's exact structured/text roundtrip, randomized physical fields,
truncation, padding preservation, target units/page latches/features, and a real
mixed-width seven-instruction PIC18 routine assembled by gpasm. The generated
Rust crates include full-corpus tests plus an external public-API/template
consumer; PIC18 includes the same real routine and target checks.

Reproduction tools are in `tools`. Artifacts and built gputils1.5.2 live under
`~/Documents/Developer/go-mkasm/architecture-expansion/pic`. Set
`MKASM_PIC_ORACLE` to its `oracle` directory and `MKASM_PIC_GENERATE` to its
`generated` directory when running the optional export/generation tests.
Run `tools/ghidra-oracle.py --artifacts <directory>` for the complete Ghidra pass,
`tools/gputils-oracle.py --artifacts <directory>` for cached gputils vectors,
and normal `cargo test --manifest-path <crate>/Cargo.toml --lib --test consumer`
for each generated stream. The corpus validates representative operand values
and all imported forms; it does not exhaust every possible operand combination.

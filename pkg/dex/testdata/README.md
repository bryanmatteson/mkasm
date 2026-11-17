# DEX corpus and independent byte fixtures

`dex_instruction_list.h` is the complete unmodified upstream AOSP ART source
from tag `android-16.0.0_r1`, commit
`ed6c006bd06ae060bd9698fd2cb25c4865512ec3`:

<https://android.googlesource.com/platform/art/+/refs/tags/android-16.0.0_r1/libdexfile/dex/dex_instruction_list.h>

Its SHA-256 is
`6dec605fb0d44317eb8534fe7c186d6d0fdeb651375f618de5a929f76d60ef45`.
The original copyright and Apache 2.0 notice remain in that source, and the
license text is retained in `APACHE-2.0.txt`. Format layout, payload behavior,
and release availability follow the AOSP references:

- <https://source.android.com/docs/core/runtime/instruction-formats>
- <https://source.android.com/docs/core/runtime/dalvik-bytecode>
- <https://source.android.com/docs/core/runtime/dex-format>

`Oracle.java` obtains bytes from smali/dexlib2's independent
`InstructionWriter`, using instruction-interface proxies and identifier pool
indices of five. It contains no mkasm layout implementation. Its 230 output
rows in `dexlib-oracle.tsv` include all 224 standard opcodes, the three
payloads, and three extra array-width variants. The fixture is also checked
without an installed Java toolchain.

`Example.smali` is this project's source for the five-method real module in
`example.dex`. The latter was assembled using smali 3.0.9 with `--api 28`
(DEX 039). Tests regenerate it, read its actual class-data/code-item structure,
round-trip every code item, and exercise baksmali disassembly and reassembly.
SHA-256: `88f31857cbe999373b2b7ef30c257795d53335c7c972c8be489cb9ec9b380f84`.

Independent tool release:
<https://github.com/baksmali/smali/releases/tag/3.0.9>

- `smali-3.0.9-fat-release.jar` SHA-256:
  `b5e2aa019c49ddaf7b2cace80f60ebbfd61f7ac18e7a3dea1075bec8779cc37a`
- `baksmali-3.0.9-fat-release.jar` SHA-256:
  `1b206070701b2145bd1e6204abd6c14fea877f335486845cd4df149bf5f79c2e`

The tool jars are external validation artifacts and are not vendored into
this package. Generated Rust tests use these independent bytes and the actual
DEX code-item bytes, rather than deriving expected bytes from the Rust codec.

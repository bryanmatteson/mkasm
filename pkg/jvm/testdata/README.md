# OpenJDK bytecode corpus

`bytecodes.cpp` and `bytecodes.hpp` are unmodified upstream OpenJDK files from
tag `jdk-21+35`:

https://github.com/openjdk/jdk/tree/jdk-21%2B35/src/hotspot/share/interpreter

The importer reads the complete standard Java `def()` records in
`bytecodes.cpp`. The header supplies an independent numeric-opcode cross-check.
The code-generation table includes HotSpot's rewritten operand formats; the
backend restores class-file big-endian fields and reserved invoke bytes as
required by the Java Virtual Machine Specification, Java SE 21, chapter 6:

https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-6.html

OpenJDK source headers and their GPL-2.0 license are retained. See
`OPENJDK-LICENSE.txt`. These files are test input data; they are not linked into
the generated codec.

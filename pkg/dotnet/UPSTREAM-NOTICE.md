# Upstream source and fixture notices

The table schemas, coded index layouts, signatures, metadata framing, and method
framing implement **ECMA-335, sixth edition, June 2012**, Partition II, §§22–25:
https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf

The Portable PDB table and sequence point layouts implement the Microsoft .NET
runtime v10.0.0 Portable PDB Metadata specification:
https://github.com/dotnet/runtime/blob/v10.0.0/docs/design/specs/PortablePdb-Metadata.md

PE headers follow Microsoft's PE/COFF specification:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

The ReadyToRun section layouts, native integer/array encodings, entry-point maps
and unwind lengths follow the MIT-licensed .NET runtime v10.0.12 readers:
https://github.com/dotnet/runtime/tree/v10.0.12/src/coreclr/tools/aot/ILCompiler.Reflection.ReadyToRun
https://github.com/dotnet/runtime/blob/v10.0.12/src/coreclr/inc/readytorun.h
The corresponding .NET Foundation license is reproduced below.

The Go and Rust readers and C# fixture/oracle sources are project code under the
repository MIT license. The pinned fixtures were compiled by Microsoft .NET SDK 10.0.401;
the JSON expectations were produced by System.Reflection.Metadata/PEReader
10.0.12. The fixture does not run P/Invoke or load arbitrary assemblies.

## ECMA specification notice

```text
"COPYRIGHT NOTICE

© <2012> Ecma International
This document may be copied, published and distributed to others, and cert ain derivative works of it
may be prepared, copied, published, and distributed, in whole or in part, provided that the above
copyright notice and this Copyright License and Disclaimer are included on all such copies and
derivative works. The only derivative works that are permissible under this Copyright License and
Disclaimer are:
(i)   works which incorporate all or portion of this document for the purpose of providing commentary or
      explanation (such as an annotated version of the document),
(ii) works which incorporate all or portion of this document for the purpose of incorporating features
     that provide accessibility,
(iii) translations of this document into languages other than English and into different formats and
(iv) works by making use of this specification in standard conformant products by implementing (e.g.
     by copy and paste wholly or partly) the functionality therein.
However, the content of this document itself may not be modified in any way, including by removing the
copyright notice or references to Ecma International, except as required to translate it into languages
other than English or into a different format.
The official version of an Ecma International document is the English language version on the Ecma
International website. In the event of discrepancies between a translated version and the official
version, the official version shall govern.
The limited permissions granted above are perpetual and will not be revoked by Ecma International or
its successors or assigns.
This document and the information contained herein is provided on an "AS IS" basis and ECMA
INTERNATIONAL DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE
ANY OWNERSHIP RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR
A PARTICULAR PURPOSE."
```

## Microsoft runtime specification license

```text
The MIT License (MIT)

Copyright (c) .NET Foundation and Contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

The original Rust embedded-PDB inflater implements RFC 1951's raw DEFLATE data
format, including stored, fixed-Huffman, and dynamic-Huffman blocks:
https://www.rfc-editor.org/rfc/rfc1951
No third-party decompressor implementation is incorporated.

# Mkasm README media

`icon.svg` is an editable vector asset. `demo.gif` records real commands and
output, with no UI or API mocks.

Install Python 3, [VHS](https://github.com/charmbracelet/vhs), and its FFmpeg and
TTY dependencies, plus the project's normal build toolchain. From the root:

```sh
python3 scripts/record-readme-demo.py /absolute/path/to/ISA_A64_xml.tar
```

The recorder builds the actual Mkasm CLI, generates a dependency-free Go A64
codec from the supplied Arm XML corpus, and runs an exact ADD encoding through
its generated encoder and decoder. The program asserts both the expected word
and encoding identity before recording.

Supply an XML directory, a tar archive, or a URL accepted by Mkasm. The corpus
is an input and is not redistributed here. The checked-in GIF used the Arm
A64 2026-06 XML archive; IDs and counts can change with a newer specification.

The generated module, CLI executable, example, VHS tape, and transcript are
kept in `~/Documents/Developer/go-mkasm/readme`. `README_RECORD_OUTPUT` overrides
that directory. The [tape](demo.tape) uses these real files, then the script
copies the finished GIF here.

The [recording script](../../scripts/record-readme-demo.py) publishes `demo.gif`
only after the example and recording finish successfully.

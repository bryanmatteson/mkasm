#!/usr/bin/env python3
"""Generate and exercise an A64 Go codec, then record the actual commands."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("corpus", help="Arm A64 XML directory, tar archive, or URL")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
output = Path(os.environ.get("README_RECORD_OUTPUT", Path.home() / "Documents/Developer/go-mkasm/readme")).expanduser().resolve()
output.mkdir(parents=True, exist_ok=True)
corpus = args.corpus if args.corpus.startswith(("https://", "http://")) else str(Path(args.corpus).expanduser().resolve())
binary = output / "mkasm"
limiter = Path.home() / ".local/bin/agent-build"
prefix = [str(limiter), "--"] if limiter.exists() else []
subprocess.run(prefix + ["go", "build", "-o", str(binary), "./cmd/mkasm"], cwd=root, check=True)
subprocess.run([str(binary), "--codegen", "go", "--output", str(output / "aarch64"), corpus], check=True)
(output / "codec.go").write_text('''package main

import (
    "fmt"
    "aarch64/encoders"
    "aarch64/decoders"
)

func main() {
    word, err := encoders.EncodeWithFields("ADD_64_addsub_imm",
        map[string]uint64{"Rd": 0, "Rn": 1, "imm12": 42})
    if err != nil { panic(err) }
    insn, err := decoders.Decode(word)
    if err != nil { panic(err) }
    if word != 0x9100a820 || insn.EncodingID != "ADD_64_addsub_imm" {
        panic("encoding round trip failed")
    }
    fmt.Printf("0x%08x → %s\\n", word, insn.EncodingID)
    fmt.Printf("Rd=%d  Rn=%d  imm12=%d\\n", insn.Fields["Rd"], insn.Fields["Rn"], insn.Fields["imm12"])
}
''')
text = subprocess.check_output(prefix + ["go", "run", "../codec.go"], cwd=output / "aarch64", text=True)
(output / "transcript.txt").write_text(text)
tape = output / "demo.tape"
tape.write_text((root / "docs/assets/demo.tape").read_text().replace("Output docs/assets/demo.gif", "Output demo.gif"))
env = dict(os.environ, README_DEMO_DIR=str(output), README_DEMO_BIN=str(binary), MKASM_CORPUS=corpus)
subprocess.run(prefix + ["vhs", str(tape)], cwd=output, env=env, check=True, timeout=180)
shutil.copyfile(output / "demo.gif", root / "docs/assets/demo.gif")
print("Recorded docs/assets/demo.gif")

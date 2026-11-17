#!/usr/bin/env python3
"""Generate real input corpora through mkasm and test the resulting Rust crates.

Example:
  python3 scripts/validate-architectures.py --mkasm ./dist/mkasm \
    --output ~/Documents/Developer/go-mkasm/generated-validation \
    --spec riscv64=/path/to/riscv-opcodes --spec avr=/path/to/avr.json

No sources are fetched and no toolchains are installed. Source/oracle package
tests are separate: this checks the public CLI and its generated consumers.
"""

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


class JSONReader:
    """Read one JSON value at a time without retaining a complete corpus."""

    def __init__(self, stream, chunk_size=1 << 20):
        self.stream, self.chunk_size = stream, chunk_size
        self.buffer, self.position, self.eof = "", 0, False
        self.decoder = json.JSONDecoder()

    def fill(self):
        self.buffer = self.buffer[self.position:]
        self.position = 0
        chunk = self.stream.read(self.chunk_size)
        self.buffer += chunk
        self.eof = not chunk

    def peek(self):
        while True:
            while self.position < len(self.buffer) and self.buffer[self.position] in " \t\r\n":
                self.position += 1
            if self.position < len(self.buffer):
                return self.buffer[self.position]
            if self.eof:
                return ""
            self.fill()

    def take(self, character):
        if self.peek() != character:
            raise ValueError(f"expected JSON {character!r}")
        self.position += 1

    def value(self):
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer, self.position)
                # A numeric token may continue in the next input chunk.
                if end < len(self.buffer) and self.buffer[end] in " \t\r\n,]}:":
                    self.position = end
                    return value
                if self.eof and end == len(self.buffer):
                    self.position = end
                    return value
            except json.JSONDecodeError:
                pass
            if self.eof:
                raise ValueError("invalid or truncated JSON value")
            if len(self.buffer) - self.position > 64 << 20:
                raise ValueError("individual IR value exceeds 64 MiB")
            self.fill()

    def count_array(self, visit=None):
        self.take("[")
        count = 0
        if self.peek() != "]":
            while True:
                value = self.value()
                if visit is not None:
                    visit(value)
                count += 1
                if self.peek() == "]":
                    break
                self.take(",")
        self.take("]")
        return count


def summarize_catalog(path, encoding_ids=None):
    """Validate complete JSON while holding at most one instruction record."""
    summary = {}
    collected_ids, invalid_ids = set(), []
    arrays = {"encodings", "opcodes", "instructions", "definitions", "llvm", "documents", "unsupported"}
    objects = {"words", "subinstructions", "instructions", "slots"}
    with path.open() as stream:
        reader = JSONReader(stream)

        def object_fields(prefix=""):
            reader.take("{")
            seen = set()
            if reader.peek() != "}":
                while True:
                    key = reader.value()
                    if not isinstance(key, str) or key in seen:
                        raise ValueError("invalid or duplicate IR object key")
                    seen.add(key)
                    reader.take(":")
                    name = prefix + key
                    if key in arrays and reader.peek() == "[":
                        def visit(record):
                            if encoding_ids is not None and key == "encodings":
                                identifier = record.get("id") if isinstance(record, dict) else None
                                if not isinstance(identifier, str) or not identifier or identifier in collected_ids:
                                    if len(invalid_ids) < 8:
                                        invalid_ids.append(identifier)
                                else:
                                    collected_ids.add(identifier)
                        summary[name] = reader.count_array(visit)
                    elif key in objects and reader.peek() == "{":
                        object_fields(name + ".")
                    else:
                        value = reader.value()
                        if not prefix and key in {"schema", "architecture"}:
                            summary[key] = value
                    if reader.peek() == "}":
                        break
                    reader.take(",")
            reader.take("}")

        object_fields()
        if reader.peek():
            raise ValueError("trailing IR JSON data")
    # x86 has its existing FormID schema and independent complete-form tests.
    # Defer this decision until the root object is complete: JSON key order is
    # not a contract, and a schema may follow the instruction array.
    if encoding_ids is not None and summary.get("schema") != "mkasm.x86.v1":
        if invalid_ids:
            raise ValueError(f"invalid or duplicate encoding IDs: {invalid_ids!r}")
        encoding_ids.update(collected_ids)
    return summary


def validate_corpus_ledger(path, expected):
    """Compare actual successful runtime cases with every exported source ID."""
    seen = set()
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 3 or not fields[0] or not re.fullmatch(r"(?:[0-9a-f]{2})+", fields[1]) or not fields[2]:
                raise RuntimeError(f"{path}:{number}: malformed runtime corpus case")
            identifier = fields[0]
            if identifier in seen:
                raise RuntimeError(f"{path}:{number}: duplicate runtime corpus ID {identifier}")
            if identifier not in expected:
                raise RuntimeError(f"{path}:{number}: unknown runtime corpus ID {identifier}")
            seen.add(identifier)
    missing = expected - seen
    if missing:
        raise RuntimeError(f"{path}: {len(missing)} untested corpus forms: {', '.join(sorted(missing)[:8])}")
    return len(seen)


def generated_files(crate):
    for directory, directories, files in os.walk(crate):
        directories[:] = [name for name in directories if name not in {"target", ".git"}]
        for name in files:
            source = Path(directory) / name
            relative = source.relative_to(crate)
            if relative != Path("Cargo.lock"):
                yield source, relative


def snapshot_generated_crate(crate):
    """Hash the tested source before regeneration can replace its files."""
    snapshot = {}
    for source, relative in generated_files(crate):
        with source.open("rb") as stream:
            snapshot[relative] = hashlib.file_digest(stream, "sha256").digest()
    if not snapshot:
        raise RuntimeError("empty generated crate cannot reuse prior tests")
    return snapshot


def compare_generated_crate(generated, tested, snapshot=None):
    """Bind a CLI output to the actual source of an already tested crate."""
    if generated.resolve() == tested.resolve() and snapshot is None:
        raise RuntimeError("same-directory reuse requires a snapshot taken before generation")
    expected = set(snapshot) if snapshot is not None else {relative for _, relative in generated_files(tested)}
    current = set()
    count = 0
    for source, relative in generated_files(generated):
        current.add(relative)
        if snapshot is not None:
            with source.open("rb") as stream:
                identical = snapshot.get(relative) == hashlib.file_digest(stream, "sha256").digest()
        else:
            reference = tested / relative
            identical = reference.is_file() and filecmp.cmp(source, reference, shallow=False)
        if not identical:
            raise RuntimeError(f"generated file differs from previously tested crate: {relative}")
        count += 1
    if current != expected:
        removed = ", ".join(str(path) for path in sorted(expected - current))
        raise RuntimeError(f"generated files removed from previously tested crate: {removed}")
    if count == 0:
        raise RuntimeError("empty generated crate cannot reuse prior tests")
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mkasm", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--spec", action="append", required=True, metavar="TARGET=SOURCE")
    parser.add_argument("--reuse-tested-crate", action="append", default=[], metavar="TARGET=DIRECTORY",
                        help="compare every generated source/data file to a crate already tested in this session, avoiding an equivalent rebuild")
    args = parser.parse_args()
    executable = args.mkasm.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve()
    cases = []
    for spec in args.spec:
        target, separator, source = spec.partition("=")
        if not separator or not re.fullmatch(r"[a-z0-9_-]+", target):
            parser.error(f"invalid --spec {spec!r}; use canonical TARGET=SOURCE")
        if target in {case[0] for case in cases}:
            parser.error(f"duplicate target {target}")
        cases.append((target, Path(source).expanduser().resolve(strict=True)))
    reused = {}
    for item in args.reuse_tested_crate:
        target, separator, path = item.partition("=")
        if not separator or target not in {case[0] for case in cases} or target in reused:
            parser.error(f"invalid --reuse-tested-crate {item!r}")
        reused[target] = Path(path).expanduser().resolve(strict=True)
        if not reused[target].is_dir():
            parser.error(f"tested crate must be a directory: {reused[target]}")
    # A dedicated output folder avoids adopting unrelated Cargo projects.
    marker = output / ".mkasm-architecture-validation"
    if output.exists() and any(output.iterdir()) and not marker.exists():
        parser.error(f"output must be empty or previously created by this script: {output}")
    output.mkdir(parents=True, exist_ok=True)
    marker.write_text("Generated architecture consumer validation\n")
    (output / "results.json").unlink(missing_ok=True)
    members, packages, results, corpus_ids = [], set(), [], {}
    for target, source in cases:
        print(f"Generating {target} from {source}", flush=True)
        crate = output / target
        snapshot = None
        if target in reused and reused[target] == crate.resolve():
            snapshot = snapshot_generated_crate(crate)
        with (output / f"{target}.log").open("w") as log:
            ir_path = output / f"{target}.json"
            with ir_path.open("w") as ir:
                subprocess.run([str(executable), "--arch", target, "--json", str(source)],
                               check=True, stdout=ir, stderr=log)
            identifiers = set()
            catalog = summarize_catalog(ir_path, identifiers)
            if identifiers:
                corpus_ids[target] = identifiers
            if catalog.get("architecture") != target:
                raise RuntimeError(f"{target}: unexpected architecture in exported IR")
            subprocess.run([str(executable), "--arch", target, "--codegen", "rust",
                            "--output", str(crate), str(source)], check=True, stdout=log, stderr=log)
        manifest = tomllib.loads((crate / "Cargo.toml").read_text())
        package = manifest["package"]["name"]
        if package in packages:
            raise RuntimeError(f"{target}: duplicate generated package {package}; validate shared mode crates separately")
        if not (crate / "LICENSE").is_file():
            raise RuntimeError(f"{target}: generated runtime license missing")
        test_sources = [crate / "src/lib.rs", *sorted((crate / "tests").glob("*.rs"))]
        if not any(re.search(r"#\s*\[\s*test\s*\]", path.read_text()) for path in test_sources):
            raise RuntimeError(f"{target}: generated project has no executable behavior tests")
        packages.add(package)
        if target not in reused:
            members.append(target)
        if "words.encodings" in catalog:  # Packet-framed Hexagon source forms.
            count = catalog["words.encodings"] + catalog.get("subinstructions.encodings", 0)
        elif catalog.get("schema") == "mkasm.ptx.registry.v1":
            count = catalog["llvm"]
        elif "instructions.encodings" in catalog:  # Scalar Xtensa plus configured FLIX slots.
            count = catalog["instructions.encodings"] + catalog.get("slots.encodings", 0)
        else:
            count = next((catalog[key] for key in ("encodings", "opcodes", "instructions", "definitions") if key in catalog), 0)
        if count == 0:
            raise RuntimeError(f"{target}: empty exported instruction corpus")
        unsupported = catalog.get("unsupported", sum(value for key, value in catalog.items() if key.endswith(".unsupported")))
        result = {"architecture": target, "source": str(source), "package": package,
                  "forms": count, "unsupported": unsupported}
        if catalog.get("schema") == "mkasm.ptx.registry.v1":
            result.update(documents=catalog["documents"], textual=True)
        if target in reused:
            compared = compare_generated_crate(crate, reused[target], snapshot)
            result.update(tests="identical_to_previously_tested_crate", tested_crate=str(reused[target]), compared_files=compared)
            if snapshot is not None:
                result["verified_against_pre_generation_hashes"] = True
            print(f"Matched {compared} generated {target} files to the already tested crate", flush=True)
        else:
            result["tests"] = "cargo"
        results.append(result)
    (output / "Cargo.toml").write_text("[workspace]\nresolver = \"2\"\nmembers = " + json.dumps(members) + "\nexclude = " + json.dumps(sorted(reused)) + "\n")
    print(f"Testing {len(members)} generated Rust libraries", flush=True)
    environment = os.environ.copy()
    environment["RUSTFLAGS"] = " ".join(filter(None, [environment.get("RUSTFLAGS"), "-D warnings"]))
    ledger_directory = output / "corpus-ledgers"
    ledger_directory.mkdir(exist_ok=True)
    for target in members:
        (ledger_directory / f"{target}.tsv").unlink(missing_ok=True)
    environment["MKASM_CORPUS_LEDGER_DIR"] = str(ledger_directory)
    if members:
        subprocess.run(["cargo", "test", "--workspace", "--lib", "--tests", "--no-fail-fast"], cwd=output, env=environment, check=True)
    for result in results:
        target = result["architecture"]
        if target in corpus_ids and target not in reused:
            result["corpus_cases"] = validate_corpus_ledger(ledger_directory / f"{target}.tsv", corpus_ids[target])
            result["samples_per_form"] = 3
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"Passed {len(cases)} CLI / generated-library consumers ({len(members)} Cargo, {len(reused)} identical tested crates); details: {output}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"architecture validation failed: {error}", file=sys.stderr)
        sys.exit(1)

"""Behavior checks for bounded corpus IR validation (standard library only)."""

import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("validate_architectures", Path(__file__).with_name("validate-architectures.py"))
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class CatalogSummaryTests(unittest.TestCase):
    def test_runtime_ledger_requires_exact_source_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cpu.tsv"
            expected = {"first", "second"}
            path.write_text('first\t8001\t"mov r1"\nsecond\t8102\t"mov r2"\n')
            self.assertEqual(validator.validate_corpus_ledger(path, expected), 2)
            for text in ('first\t8001\t"mov r1"\n',
                         'first\t8001\t"mov r1"\nfirst\t8002\t"mov r2"\n',
                         'other\t8001\t"mov r1"\n', 'first\txx\t"mov r1"\n'):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(RuntimeError):
                    validator.validate_corpus_ledger(path, expected)

    def test_collects_nested_ids_and_rejects_source_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text('{"words":{"encodings":[{"id":"word"}]},"subinstructions":{"encodings":[{"id":"sub"}]}}')
            identifiers = set()
            validator.summarize_catalog(path, identifiers)
            self.assertEqual(identifiers, {"word", "sub"})
            path.write_text('{"encodings":[{"id":"same"},{"id":"same"}]}')
            with self.assertRaises(ValueError):
                validator.summarize_catalog(path, set())

    def test_x86_form_ids_retain_the_existing_schema_in_any_key_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x86.json"
            for source in ('{"schema":"mkasm.x86.v1","encodings":[{"FormID":"ADD/0"}]}',
                           '{"encodings":[{"FormID":"ADD/0"}],"schema":"mkasm.x86.v1"}'):
                path.write_text(source)
                identifiers = set()
                self.assertEqual(validator.summarize_catalog(path, identifiers)["encodings"], 1)
                self.assertEqual(identifiers, set())

    def test_same_directory_reuse_checks_pre_generation_source(self):
        with tempfile.TemporaryDirectory() as directory:
            crate = Path(directory)
            source = crate / "lib.rs"
            source.write_text("pub const VALUE:u8=1;\n")
            with self.assertRaises(RuntimeError):
                validator.compare_generated_crate(crate, crate)
            snapshot = validator.snapshot_generated_crate(crate)
            source.write_text("pub const VALUE:u8=1;\n")
            self.assertEqual(validator.compare_generated_crate(crate, crate, snapshot), 1)
            source.write_text("pub const VALUE:u8=2;\n")
            with self.assertRaises(RuntimeError):
                validator.compare_generated_crate(crate, crate, snapshot)
            source.write_text("pub const VALUE:u8=1;\n")
            (crate / "new.rs").write_text("pub const ADDED:u8=3;\n")
            with self.assertRaises(RuntimeError):
                validator.compare_generated_crate(crate, crate, snapshot)

    def test_reuse_requires_identical_generated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            generated, tested = Path(directory) / "generated", Path(directory) / "tested"
            for path in (generated, tested):
                (path / "src").mkdir(parents=True)
                (path / "Cargo.toml").write_text("[package]\nname='example'\n")
                (path / "src/lib.rs").write_text("pub const VALUE:u8=1;\n")
            (generated / "Cargo.lock").write_text("local lockfile")
            self.assertEqual(validator.compare_generated_crate(generated, tested), 2)
            (tested / "src/lib.rs").write_text("pub const VALUE:u8=2;\n")
            with self.assertRaises(RuntimeError):
                validator.compare_generated_crate(generated, tested)
            (tested / "src/lib.rs").unlink()
            with self.assertRaises(RuntimeError):
                validator.compare_generated_crate(generated, tested)

    def test_reuse_rejects_removed_generated_files(self):
        with tempfile.TemporaryDirectory() as directory:
            generated, tested = Path(directory) / "generated", Path(directory) / "tested"
            for path in (generated, tested):
                path.mkdir()
                (path / "lib.rs").write_text("mod runtime;\n")
                (path / "runtime.rs").write_text("pub const VALUE:u8=1;\n")
            snapshot = validator.snapshot_generated_crate(generated)
            (generated / "runtime.rs").unlink()
            # Equal remaining files do not prove the current crate can build.
            for reference, prior in ((tested, None), (generated, snapshot)):
                with self.subTest(reference=reference), self.assertRaises(RuntimeError):
                    validator.compare_generated_crate(generated, reference, prior)

    def summarize(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(text)
            return validator.summarize_catalog(path)

    def test_all_instruction_shapes(self):
        for key in ("encodings", "opcodes", "instructions", "definitions", "llvm"):
            source = {"schema": "example", "architecture": "cpu", key: [{"bits": [1, 2]}, {}], "unsupported": [{"id": "bad"}]}
            summary = self.summarize(json.dumps(source))
            self.assertEqual(summary, {"schema": "example", "architecture": "cpu", key: 2, "unsupported": 1})

    def test_packet_bundle_and_null_tables(self):
        self.assertEqual(self.summarize('{"words":{"encodings":[{},{}]},"subinstructions":{"encodings":[{}]}}'),
                         {"words.encodings": 2, "subinstructions.encodings": 1})
        self.assertEqual(self.summarize('{"instructions":{"encodings":[{}]},"slots":null}'),
                         {"instructions.encodings": 1})
        self.assertEqual(self.summarize('{"instructions":{"encodings":[{}]},"slots":{"encodings":null}}'),
                         {"instructions.encodings": 1})

    def test_chunk_boundaries_and_numeric_tokens(self):
        source = '[1e+12,-3.14,12345,true,null,"escaped \\" text",{"unicode":"λ","nested":[1,2]}]'
        expected = json.loads(source)
        for size in (1, 2, 3, 7, 64):
            reader = validator.JSONReader(io.StringIO(source), chunk_size=size)
            self.assertEqual(reader.value(), expected)
            self.assertEqual(reader.peek(), "")
            reader = validator.JSONReader(io.StringIO(source), chunk_size=size)
            self.assertEqual(reader.count_array(), len(expected))
            self.assertEqual(reader.peek(), "")

    def test_large_stream_and_complete_validation(self):
        records = [{"id": str(i), "names": ["r" + str(n) for n in range(50)]} for i in range(5000)]
        summary = self.summarize(json.dumps({"architecture": "cpu", "encodings": records, "profiles": {"default": ["x"]}}))
        self.assertEqual(summary["encodings"], 5000)
        for invalid in ('', '{"encodings":[{}}', '{"encodings":[{},]}', '{"encodings":[]} trailing',
                        '{"architecture":"a","architecture":"b"}', '{"encodings":[{"x":1e}]}'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.summarize(invalid)


if __name__ == "__main__":
    unittest.main()

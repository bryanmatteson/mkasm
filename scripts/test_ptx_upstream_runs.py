"""Keep the primary LLVM RUN extractor complete and free of shell execution."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("ptx_runs", Path(__file__).resolve().parents[1] / "pkg/ptx/testdata/upstream-runs.py")
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


class UpstreamRunsTests(unittest.TestCase):
    def parse(self, source):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "llvm/test/CodeGen/NVPTX"
            path.mkdir(parents=True)
            (path / "program.ll").write_text(source)
            return extractor.read_runs(Path(root))

    def test_all_native_commands_and_continuations_are_retained(self):
        runs = self.parse("; RUN: llc -mtriple=nvptx64 -mattr=+ptx86 < %s | FileCheck %s\n"
                          "; RUN: %if ptxas %{ llc -mtriple=nvptx64 \\\n"
                          "; RUN: -mcpu=sm_100a < %s | %ptxas-verify -arch sm_100a %}\n"
                          "; RUN: %if ptxas %{ llc -mtriple=nvptx %s | %ptxas-verify -m32 %}\n")
        self.assertEqual([r["name"] for r in runs], ["program-1", "program-2"])
        self.assertEqual(runs[0]["llc"], ["-mtriple=nvptx64", "-mcpu=sm_100a"])
        self.assertEqual(runs[0]["ptxas"], ["-arch", "sm_100a"])
        self.assertEqual(runs[1]["ptxas"], ["-m32"])

    def test_missing_input_or_unrecognized_pipeline_fails(self):
        for line in ["llc -mtriple=nvptx64 | %ptxas-verify", "not llc %s | %ptxas-verify",
                     "opt < %s | %ptxas-verify", "llc %t | %ptxas-verify",
                     "llc %s | %ptxas-verify -arch", "llc %s | %ptxas-verify -arch sm_100a;",
                     "llc %s | %ptxas-verify $(echo bad)", "llc %s | %ptxas-verify -unknown"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.parse("; RUN: " + line)

    def test_empty_native_corpus_is_an_error(self):
        with self.assertRaises(ValueError):
            self.parse("; RUN: llc %s | FileCheck %s\n")

    def test_generated_ir_uses_primary_script_and_run_options(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "llvm/test/CodeGen/NVPTX"
            path.mkdir(parents=True)
            source = path / "matrix.py"
            source.write_text('# RUN: %python %s --ptx=86 > %t.ll\n'
                              '# RUN: %if ptxas %{ llc < %t.ll -mtriple=nvptx64 | %ptxas-verify -arch=sm_100a %}\n'
                              'import sys\nassert sys.argv[1:] == ["--ptx=86"]\n'
                              'print("; original primary IR")\n'
                              'unused="; RUN: not llc %s | %ptxas-verify"\n')
            with self.assertRaises(ValueError):
                extractor.read_runs(Path(root))
            runs = extractor.read_runs(Path(root), Path(root) / "output")
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["name"], "matrix-1")
            self.assertEqual(runs[0]["llc"], ["-mtriple=nvptx64"])
            self.assertEqual(Path(runs[0]["source"]).read_text(), "; original primary IR\n")


if __name__ == "__main__":
    unittest.main()

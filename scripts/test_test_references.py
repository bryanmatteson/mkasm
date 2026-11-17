#!/usr/bin/env python3
"""Regression checks for reference-runner false-green failure modes."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("reference_runner", Path(__file__).with_name("test-references.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReferenceExecutionTests(unittest.TestCase):
    def test_passing_package_without_requested_test_is_failure(self):
        result = runner.evaluate_events([{"Action": "pass", "Package": "example"}], ["TestOracle"], 0)
        self.assertFalse(result["passed"])
        self.assertEqual(result["missing_tests"], ["TestOracle"])

    def test_skipped_reference_child_is_failure(self):
        result = runner.evaluate_events([
            {"Action": "skip", "Test": "TestOracle/BE"},
            {"Action": "pass", "Test": "TestOracle"}], ["TestOracle"], 0)
        self.assertFalse(result["passed"])
        self.assertEqual(result["skipped"], ["TestOracle/BE"])

    def test_failed_child_is_failure_even_with_zero_exit(self):
        result = runner.evaluate_events([
            {"Action": "fail", "Test": "TestOracle/operand"},
            {"Action": "pass", "Test": "TestOracle"}], ["TestOracle"], 0)
        self.assertFalse(result["passed"])

    def test_build_error_is_failure(self):
        self.assertFalse(runner.evaluate_events([], ["TestOracle"], 1)["passed"])

    def test_every_requested_reference_must_pass(self):
        events = [{"Action": "pass", "Test": "TestAssembler"}, {"Action": "pass", "Test": "TestDecoder"}]
        self.assertTrue(runner.evaluate_events(events, ["TestAssembler", "TestDecoder"], 0)["passed"])
        self.assertFalse(runner.evaluate_events(events, ["TestAssembler", "TestDecoder", "TestOperands"], 0)["passed"])


if __name__ == "__main__":
    unittest.main()

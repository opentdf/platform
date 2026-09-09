import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("summary", Path(__file__).with_name("summarize-authz-performance.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class SummaryTests(unittest.TestCase):
    def record(self, **changes):
        row = dict(case="allowed_read", concurrency=50, resources=3, seed=4625,
                   wall_ns=150000000, median_ns=100000000, p95_ns=130000000,
                   maximum_ns=140000000, timeout_ns=30000000000, failures=0)
        row.update(changes)
        return summary.MARKER + json.dumps(row)

    def test_console_and_json_records_have_identical_rendering(self):
        record = self.record()
        console, errors = summary.render(record, "success")
        encoded, _ = summary.render(json.dumps({"Action": "output", "Output": record + "\n"}), "success")
        self.assertEqual(console, encoded)
        self.assertEqual(errors, 0)
        self.assertIn("130.00 ms | 140.00 ms | 30000.00 ms | 0 | PASS", console)

    def test_partial_failure_keeps_rows_without_gating_slow_requests(self):
        text = self.record(case="denied_user", failures=2, first_error="unavailable: unexpected EOF") + "\n" + self.record(case="allowed_read", maximum_ns=8000000000)
        rendered, errors = summary.render(text, "failure")
        self.assertEqual(errors, 0)
        self.assertIn("BDD step outcome: **failure**", rendered)
        self.assertIn("8000.00 ms | 30000.00 ms | 0 | PASS |", rendered)
        self.assertIn("| 2 | FAIL |", rendered)
        self.assertIn("unavailable: unexpected EOF", rendered)
        self.assertIn("Latency is report-only", rendered)
        self.assertLess(rendered.index("allowed_read"), rendered.index("denied_user"))

    def test_cli_handles_missing_log_after_setup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("summarize-authz-performance.py")),
                 str(Path(directory) / "missing.log"), "--bdd-outcome", "failure"],
                capture_output=True, text=True, check=True,
            )
        self.assertIn("No authorization measurements", result.stdout)
        self.assertIn("BDD step outcome: **failure**", result.stdout)

    def test_missing_and_malformed_measurements_are_not_passes(self):
        rendered, errors = summary.render("setup failed", "failure")
        self.assertIn("No authorization measurements", rendered)
        self.assertEqual(errors, 0)
        rendered, errors = summary.render(self.record() + "\n" + summary.MARKER + "{}", "failure")
        self.assertEqual(errors, 1)
        self.assertIn("malformed performance record", rendered)
        self.assertIn("allowed_read", rendered)


if __name__ == "__main__":
    unittest.main()

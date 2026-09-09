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
        row = dict(concurrency=50, requests=200, resources_requested=200, seed=4625,
                   wall_ns=150000000, median_ns=100000000, p95_ns=130000000,
                   maximum_ns=140000000, timeout_ns=30000000000, failures=0,
                   cases=[dict(name="allowed read", user="engineer", action="read", resources=["engineering"], expected=["PERMIT"], requests=100, failures=0),
                          dict(name="denied user", user="visitor", action="read", resources=["engineering"], expected=["DENY"], requests=100, failures=0)])
        row.update(changes)
        row["cases"][0]["failures"] = row["failures"]
        if row["failures"]:
            row["cases"][0]["first_error"] = "unavailable: unexpected EOF"
        return summary.MARKER + json.dumps(row)

    def test_console_and_json_records_have_identical_rendering(self):
        record = self.record()
        console, errors = summary.render(record, "success")
        encoded, _ = summary.render(json.dumps({"Action": "output", "Output": record + "\n"}), "success")
        self.assertEqual(console, encoded)
        self.assertEqual(errors, 0)
        self.assertIn("| 50 | 200 | 2/2 | 100.00 ms | 130.00 ms | 140.00 ms |", console)
        self.assertIn("Request timeout: 30 s", console)
        self.assertIn("<details>", console)
        self.assertIn("PERFORMANCE", console.upper())

    def test_failure_keeps_completed_loads_and_does_not_gate_latency(self):
        text = self.record(failures=2) + "\n" + self.record(concurrency=10, maximum_ns=8000000000)
        rendered, errors = summary.render(text, "failure")
        self.assertEqual(errors, 0)
        self.assertIn("BDD step outcome: **failure**", rendered)
        self.assertIn("8,000.00 ms", rendered)
        self.assertIn("| 0 | PASS |", rendered)
        self.assertIn("| 2 | FAIL |", rendered)
        self.assertIn("unavailable: unexpected EOF", rendered)
        self.assertIn("Performance: REPORT ONLY", rendered)
        self.assertLess(rendered.index("| 10 |"), rendered.index("| 50 |"))

    def test_unsampled_cases_remain_visible(self):
        record = json.loads(self.record().split(summary.MARKER)[1])
        record["cases"].append(dict(name="not selected", user="analyst", action="write", resources=["projects"], expected=["DENY"], requests=0, failures=0))
        rendered, errors = summary.render(summary.MARKER + json.dumps(record), "success")
        self.assertEqual(errors, 0)
        self.assertIn("| 2/3 |", rendered)
        self.assertIn("not selected | analyst | write | projects | DENY | 0 | 0 |", rendered)

    def test_cli_handles_missing_log_after_setup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("summarize-authz-performance.py")),
                 str(Path(directory) / "missing.log"), "--bdd-outcome", "failure"],
                capture_output=True, text=True, check=True,
            )
        self.assertIn("No authorization measurements", result.stdout)
        self.assertIn("BDD step outcome: **failure**", result.stdout)

    def test_malformed_and_inconsistent_counts_are_not_passes(self):
        rendered, errors = summary.render(self.record() + "\n" + summary.MARKER + "{}", "failure")
        self.assertEqual(errors, 1)
        self.assertIn("malformed performance record", rendered)
        self.assertIn("allowed read", rendered)
        for changes in (dict(requests=201), dict(resources_requested=201)):
            _, errors = summary.render(self.record(**changes), "success")
            self.assertEqual(errors, 1)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Render structured authorization measurements, including failed BDD runs."""
import argparse
import json
from pathlib import Path

MARKER = "AUTHZ_PERFORMANCE "
NUMBERS = (
    "seed", "concurrency", "resources", "wall_ns", "median_ns", "p95_ns",
    "maximum_ns", "timeout_ns", "failures",
)


def read_results(text):
    results, malformed = [], 0
    for line in text.splitlines():
        # Support both console logs and go test -json artifacts.
        if line.startswith("{"):
            try:
                output = json.loads(line).get("Output")
                if isinstance(output, str):
                    line = output
            except (ValueError, AttributeError):
                pass
        if MARKER not in line:
            continue
        try:
            result = json.loads(line.split(MARKER, 1)[1])
            if not isinstance(result.get("case"), str) or not result["case"]:
                raise ValueError("missing case")
            if any(type(result.get(key)) is not int or result[key] < 0 for key in NUMBERS):
                raise ValueError("invalid numeric field")
            if not result["concurrency"] or not result["resources"] or not result["timeout_ns"]:
                raise ValueError("invalid dimensions")
            if result["failures"] > result["concurrency"]:
                raise ValueError("invalid failure count")
            if not isinstance(result.get("first_error", ""), str):
                raise ValueError("invalid error detail")
            results.append(result)
        except (ValueError, TypeError, AttributeError):
            malformed += 1
    return sorted(results, key=lambda row: (row["concurrency"], row["case"], row["seed"])), malformed


def milliseconds(nanoseconds):
    return f"{nanoseconds / 1_000_000:.2f} ms"


def render(text, outcome):
    results, malformed = read_results(text)
    lines = ["### Authorization v2 concurrency performance", "", f"BDD step outcome: **{outcome}**.", ""]
    if results:
        lines += [
            "| Case | Concurrency | Resources | Seed | Wall | Median | p95 | Maximum | Timeout | Failures | Requests | First error |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
        ]
        for row in results:
            case = row["case"].replace("|", "\\|").replace("\n", " ").replace("\r", " ")
            status = "FAIL" if row["failures"] else "PASS"
            cells = [case, str(row["concurrency"]), str(row["resources"]), str(row["seed"])]
            cells += [milliseconds(row[key]) for key in ("wall_ns", "median_ns", "p95_ns", "maximum_ns", "timeout_ns")]
            error = row.get("first_error", "").replace("|", "\\|").replace("\n", " ").replace("\r", " ")
            cells += [str(row["failures"]), status, error]
            lines.append("| " + " | ".join(cells) + " |")
        lines += ["", f"Reported {len(results)} completed case batches. Missing measurements are not passes."]
    else:
        lines.append("No authorization measurements were produced. Check BDD setup and logs; this is not a passing performance result.")
    if malformed:
        lines += ["", f"**Summary error: {malformed} malformed performance record(s).**"]
    lines += ["", "Fixture setup is excluded. PASS means requests completed with the expected decisions. Failures include request errors, timeouts, and incorrect decisions. Latency is report-only until a baseline is established; the request timeout is not a latency target.", ""]
    return "\n".join(lines), malformed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    parser.add_argument("--bdd-outcome", default="unknown", choices=["success", "failure", "cancelled", "skipped", "unknown"])
    args = parser.parse_args()
    text = args.log.read_text() if args.log.exists() else ""
    summary, malformed = render(text, args.bdd_outcome)
    print(summary)
    return bool(malformed)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Render mixed authorization load measurements, including failed BDD runs."""
import argparse
import json
from pathlib import Path

MARKER = "AUTHZ_PERFORMANCE "
NUMBERS = (
    "seed", "concurrency", "requests", "resources_requested", "wall_ns",
    "median_ns", "p95_ns", "maximum_ns", "timeout_ns", "failures",
)


def validate_result(result):
    if any(type(result.get(key)) is not int or result[key] < 0 for key in NUMBERS):
        raise ValueError("invalid numeric field")
    if not result["concurrency"] or result["requests"] < result["concurrency"] or not result["timeout_ns"]:
        raise ValueError("invalid workload dimensions")
    cases = result.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("missing case results")
    names = set()
    for case in cases:
        if any(not isinstance(case.get(key), str) or not case[key] for key in ("name", "user", "action")):
            raise ValueError("invalid case identity")
        if case["name"] in names:
            raise ValueError("duplicate case")
        names.add(case["name"])
        if any(type(case.get(key)) is not int or case[key] < 0 for key in ("requests", "failures")):
            raise ValueError("invalid case counts")
        if case["failures"] > case["requests"] or not isinstance(case.get("first_error", ""), str):
            raise ValueError("invalid case failures")
        resources, expected = case.get("resources"), case.get("expected")
        if not isinstance(resources, list) or not resources or any(not isinstance(r, str) or not r for r in resources):
            raise ValueError("invalid resources")
        if not isinstance(expected, list) or len(resources) != len(expected) or any(d not in ("PERMIT", "DENY") for d in expected):
            raise ValueError("invalid expectations")
    if sum(c["requests"] for c in cases) != result["requests"] or sum(c["failures"] for c in cases) != result["failures"]:
        raise ValueError("case counts do not match workload totals")
    if sum(c["requests"] * len(c["resources"]) for c in cases) != result["resources_requested"]:
        raise ValueError("resource counts do not match workload total")


def read_results(text):
    results, malformed = [], 0
    for line in text.splitlines():
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
            validate_result(result)
            results.append(result)
        except (ValueError, TypeError, AttributeError, KeyError):
            malformed += 1
    return sorted(results, key=lambda row: (row["concurrency"], row["seed"])), malformed


def milliseconds(nanoseconds):
    return f"{nanoseconds / 1_000_000:,.2f} ms"


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def render(text, outcome):
    results, malformed = read_results(text)
    lines = ["### Authorization v2 concurrency performance", "", f"BDD step outcome: **{outcome}**.", "",
             "**Workload:** workers continuously draw from the entitlement case pool. Each request independently selects a case; users, actions, and resources vary within the same load run.", "",
             "**Performance: REPORT ONLY.** Correctness PASS means all requests completed with the expected resource decisions. Errors and request timeouts fail; no latency baseline is enforced.", ""]
    if results:
        lines += [
            "| Concurrency | Requests | Cases used | Median | p95 | Maximum | Requests/s | Failures | Correctness |",
            "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
        for row in results:
            used = sum(c["requests"] > 0 for c in row["cases"])
            rate = f"{row['requests'] / (row['wall_ns'] / 1_000_000_000):,.2f}" if row["wall_ns"] else "n/a"
            cells = [str(row["concurrency"]), str(row["requests"]), f"{used}/{len(row['cases'])}"]
            cells += [milliseconds(row[key]) for key in ("median_ns", "p95_ns", "maximum_ns")]
            cells += [rate, str(row["failures"]), "FAIL" if row["failures"] else "PASS"]
            lines.append("| " + " | ".join(cells) + " |")
        lines += ["", "Fixture setup is excluded. Latency covers the whole multi-resource request. Throughput includes failed requests; inspect correctness alongside it. Cases selected zero times remain visible below."]
        for row in results:
            lines += ["", "<details>", f"<summary>Case selection and failures at concurrency {row['concurrency']}</summary>", "",
                      f"Seed: {row['seed']}. Request timeout: {row['timeout_ns'] / 1_000_000_000:g} s. Load duration: {row['wall_ns'] / 1_000_000_000:,.2f} s. Resources requested: {row['resources_requested']:,}.", "",
                      "| Case | User | Action | Resources | Expected decisions | Selected | Failures | First error |",
                      "| --- | --- | --- | --- | --- | ---: | ---: | --- |"]
            for case in row["cases"]:
                cells = [case["name"], case["user"], case["action"], ", ".join(case["resources"]), ", ".join(case["expected"]),
                         case["requests"], case["failures"], case.get("first_error", "")]
                lines.append("| " + " | ".join(cell(c) for c in cells) + " |")
            lines += ["", "</details>"]
    else:
        lines.append("No authorization measurements were produced. Check BDD setup and logs; this is not a passing performance result.")
    if malformed:
        lines += ["", f"**Summary error: {malformed} malformed performance record(s).**"]
    return "\n".join(lines) + "\n", malformed


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

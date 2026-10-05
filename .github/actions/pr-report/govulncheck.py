"""Aggregate structured per-module receipts; absence never means success."""

import json
import os
from pathlib import Path

MODULES = {
    "examples",
    "otdfctl",
    "sdk",
    "service",
    "lib/ocrypto",
    "lib/fixtures",
    "lib/flattening",
    "lib/identifier",
    "tests-bdd",
}


def aggregate(directory):
    results = {}
    for path in Path(directory).glob("*.json"):
        data = json.loads(path.read_text())
        if set(data) != {"module", "outcome", "run", "attempt"}:
            raise ValueError("Invalid govulncheck receipt")
        module = data["module"]
        if module not in MODULES or module in results:
            raise ValueError("Unknown/duplicate module")
        if (
            str(data["run"]) != os.environ["GITHUB_RUN_ID"]
            or str(data["attempt"]) != os.environ["GITHUB_RUN_ATTEMPT"]
        ):
            raise ValueError("Stale receipt")
        if data["outcome"] not in {"success", "failure", "skipped", "cancelled"}:
            raise ValueError("Invalid outcome")
        results[module] = data["outcome"]
    if any(outcome == "failure" for outcome in results.values()):
        status = "failed"
    elif set(results) == MODULES and all(
        outcome == "success" for outcome in results.values()
    ):
        status = "passed"
    elif any(outcome == "cancelled" for outcome in results.values()):
        status = "cancelled"
    else:
        status = "unavailable"
    details = "\n".join(
        f"{module}: {results.get(module, 'unavailable')}" for module in sorted(MODULES)
    )
    return status, details


if __name__ == "__main__":
    status, details = aggregate("govulncheck-results")
    Path("govulncheck-summary.txt").write_text(
        {
            "passed": "All modules completed govulncheck without findings.",
            "failed": "Govulncheck reported findings or failed; inspect the run for diagnostics.",
            "cancelled": "Govulncheck was cancelled.",
            "unavailable": "Some modules have no completed govulncheck result.",
        }[status]
    )
    Path("govulncheck-details.txt").write_text(details)
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"status={status}\n")

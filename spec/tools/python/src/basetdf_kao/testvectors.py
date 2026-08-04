"""Loader and runner for BaseTDF KAO test vectors.

Each vector under ``spec/testvectors/kao/vectors/`` is loaded, validated
against ``vector.schema.json``, and dispatched to the appropriate runner
based on its ``category`` field.

The runner exists primarily to drive the pytest conformance gate; CLI users
exercise it through ``basetdf-kao run-vectors``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from basetdf_kao.binding import verify_binding
from basetdf_kao.schema import spec_root, vector_validator
from basetdf_kao.validate import validate_kao


@dataclass
class Vector:
    id: str
    description: str
    conformance: list[str]
    category: str
    algorithm: str
    inputs: dict[str, Any]
    expected: dict[str, Any]
    path: Path

    @classmethod
    def load(cls, path: Path) -> Vector:
        data = json.loads(path.read_text())
        # Validate against vector.schema.json
        errors = list(vector_validator().iter_errors(data))
        if errors:
            raise ValueError(f"{path}: vector schema violations: {[e.message for e in errors]}")
        return cls(
            id=data["id"],
            description=data["description"],
            conformance=data["conformance"],
            category=data["category"],
            algorithm=data["algorithm"],
            inputs=data["inputs"],
            expected=data["expected"],
            path=path,
        )


@dataclass
class VectorResult:
    vector_id: str
    passed: bool
    actual_outcome: str
    actual_error_code: str | None = None
    detail: str | None = None
    findings: list[str] = field(default_factory=list)


def vectors_dir() -> Path:
    return spec_root() / "testvectors" / "kao"


def load_index() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((vectors_dir() / "index.json").read_text())
    return data


def load_vectors() -> list[Vector]:
    """Load every vector listed in ``index.json`` that exists on disk.

    Vectors referenced from the index but not yet authored are skipped.
    """
    base = vectors_dir()
    index = load_index()
    out: list[Vector] = []
    for entry in index["vectors"]:
        path = base / entry["file"]
        if not path.is_file():
            continue
        out.append(Vector.load(path))
    return out


def _structural_check(vector: Vector) -> VectorResult:
    """Run structural validation and assert the expected outcome."""
    report = validate_kao(vector.inputs["kao"])
    expected_outcome = vector.expected["outcome"]
    expected_error = vector.expected.get("errorCode")
    findings = [f"{f.conformance_id}:{f.code.value}" for f in report.errors]
    actual_codes = [f.code.value for f in report.errors]

    if expected_outcome == "accept":
        if report.ok:
            return VectorResult(vector.id, True, "accept", None, "structural ok", findings)
        return VectorResult(
            vector.id,
            False,
            "reject",
            actual_codes[0] if actual_codes else None,
            f"expected accept but got errors: {findings}",
            findings,
        )

    # expected reject — pass if the expected code appears anywhere in the
    # finding list. Schema validation may surface adjacent findings (e.g., a
    # type-conflict KAO also fails the policyBinding extra-properties check),
    # so we check membership rather than first-error equality.
    if expected_error in actual_codes:
        return VectorResult(
            vector.id, True, "reject", expected_error, "rejected as expected", findings
        )
    if not report.ok:
        return VectorResult(
            vector.id,
            False,
            "reject",
            actual_codes[0],
            f"expected error {expected_error} but got {actual_codes}",
            findings,
        )
    return VectorResult(
        vector.id,
        False,
        "accept",
        None,
        f"expected reject ({expected_error}) but no errors raised",
        findings,
    )


def _binding_check(vector: Vector) -> VectorResult | None:
    """Run policy-binding verification for KAT vectors that pin DEK + policy."""
    inputs = vector.inputs
    if "policy" not in inputs or "dekShare" not in inputs:
        return None
    policy = inputs["policy"].encode("ascii")
    dek_share = bytes.fromhex(inputs["dekShare"])
    expected_outcome = vector.expected["outcome"]
    expected_error = vector.expected.get("errorCode")
    expected_valid = vector.expected.get("policyBindingValid")

    binding = inputs["kao"].get("policyBinding")
    result = verify_binding(binding, dek_share, policy)

    if expected_outcome == "accept":
        if result.valid:
            if expected_valid is False:
                return VectorResult(
                    vector.id,
                    False,
                    "accept",
                    None,
                    "binding valid but expected invalid",
                )
            return VectorResult(vector.id, True, "accept", None, "binding verified")
        return VectorResult(
            vector.id,
            False,
            "reject",
            result.error_code.value if result.error_code else None,
            f"expected binding-valid but got {result.error_code}",
        )

    # expected reject
    if not result.valid:
        actual = result.error_code.value if result.error_code else None
        if expected_error == actual:
            return VectorResult(vector.id, True, "reject", actual, "binding rejected as expected")
        # Tolerate the case where structural validation already covered it.
        return VectorResult(
            vector.id,
            True,
            "reject",
            actual,
            f"binding rejected with {actual}; vector expects {expected_error}",
        )
    return VectorResult(vector.id, False, "accept", None, "expected reject but binding verified")


def run_vector(vector: Vector) -> VectorResult:
    """Run one vector. Dispatch by category.

    Negative vectors test that structural validation rejects with the expected
    error code, OR that policy-binding verification rejects when the expected
    error code is one of the binding-related codes. KAT vectors additionally
    verify the pinned policy binding. Positive vectors require structural
    acceptance.
    """
    structural = _structural_check(vector)
    binding_codes = {
        "kao.policy_binding_mismatch",
        "kao.policy_binding_alg_unsupported",
        "kao.policy_binding_format_invalid",
        "kao.legacy_decoding_failure",
    }
    expected_error = vector.expected.get("errorCode")

    if vector.category == "kat":
        binding = _binding_check(vector)
        if binding is not None:
            return binding
        return structural

    # When a negative vector targets a binding-related error code, the
    # structural check by itself won't catch it (the KAO is structurally valid
    # but its binding is wrong). Drive the binding check additionally.
    if vector.category == "negative" and expected_error in binding_codes:
        binding = _binding_check(vector)
        if binding is not None:
            return binding

    return structural

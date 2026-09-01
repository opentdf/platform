"""Conformance gate: parametrized over every test vector under index.json.

Failure here indicates the implementation under test (this validator, in
this run) deviates from the spec for the cited conformance ID. To diagnose,
run ``basetdf-kao run-vectors --filter <id>`` and inspect the report.
"""

from __future__ import annotations

import pytest

from basetdf_kao.testvectors import Vector, load_vectors, run_vector


def _id(v: Vector) -> str:
    return v.id


@pytest.fixture(scope="module")
def vectors() -> list[Vector]:
    out = load_vectors()
    if not out:
        pytest.skip("no test vectors authored yet under spec/testvectors/kao/vectors/")
    return out


@pytest.mark.parametrize("vector_id", [v.id for v in load_vectors()])
def test_vector_passes(vector_id: str) -> None:
    matches = [v for v in load_vectors() if v.id == vector_id]
    assert matches, f"vector {vector_id!r} not found"
    result = run_vector(matches[0])
    assert result.passed, (
        f"vector {vector_id!r} failed: {result.detail}; findings={result.findings}"
    )

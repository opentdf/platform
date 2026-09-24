"""Unit tests for the structural validator."""

from __future__ import annotations

import base64

from basetdf_kao import ErrorCode, validate_kao


def _kao(**overrides: object) -> dict[str, object]:
    base = {
        "alg": "RSA-OAEP-256",
        "kas": "https://kas.example.com",
        "kid": "k1",
        "sid": "s-0",
        "protectedKey": base64.b64encode(b"\x00" * 256).decode("ascii"),
        "policyBinding": {"alg": "HS256", "hash": base64.b64encode(b"\x00" * 32).decode("ascii")},
    }
    base.update(overrides)
    return base


def test_baseline_v44_is_accepted() -> None:
    report = validate_kao(_kao())
    assert report.ok, [(f.code, f.message) for f in report.errors]
    assert report.normalized is not None
    assert report.normalized["alg"] == "RSA-OAEP-256"


def test_alg_type_disagreement_rejected() -> None:
    kao = _kao(type="ec-wrapped")
    report = validate_kao(kao)
    codes = [f.code for f in report.errors]
    assert ErrorCode.ALG_TYPE_CONFLICT in codes


def test_kas_url_alias_conflict() -> None:
    report = validate_kao(_kao(url="https://other.example.com"))
    codes = [f.code for f in report.errors]
    assert ErrorCode.ALIAS_CONFLICT in codes


def test_unknown_alg_rejected() -> None:
    report = validate_kao(_kao(alg="XSALSA20"))
    codes = [f.code for f in report.errors]
    # Schema rejects via enum, surfaced as schema_violation; the validator
    # also tags it with KAO-C-010 / unknown_alg in the structural pass.
    assert ErrorCode.SCHEMA_VIOLATION in codes or ErrorCode.UNKNOWN_ALG in codes


def test_missing_policy_binding_rejected() -> None:
    kao = _kao()
    del kao["policyBinding"]
    report = validate_kao(kao)
    codes = [f.code for f in report.errors]
    assert ErrorCode.POLICY_BINDING_MISSING in codes


def test_mlkem_requires_ephemeral_key() -> None:
    report = validate_kao(_kao(alg="ML-KEM-768"))
    codes = [f.code for f in report.errors]
    assert ErrorCode.EPHEMERAL_KEY_REQUIRED in codes


def test_legacy_type_wrapped_normalizes_to_rsa_oaep() -> None:
    kao = _kao()
    del kao["alg"]
    kao["type"] = "wrapped"
    report = validate_kao(kao)
    assert report.ok, [(f.code, f.message) for f in report.errors]
    assert report.normalized["alg"] == "RSA-OAEP"


def test_bare_string_policy_binding_warned_but_accepted() -> None:
    kao = _kao(policyBinding=base64.b64encode(b"\x00" * 32).decode("ascii"))
    report = validate_kao(kao)
    assert report.ok, [(f.code, f.message) for f in report.errors]
    assert any(f.code == ErrorCode.POLICY_BINDING_FORMAT_INVALID for f in report.warnings)

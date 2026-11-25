"""Unit tests for policy-binding compute and verify."""

from __future__ import annotations

import base64
import binascii

from basetdf_kao import ErrorCode
from basetdf_kao.binding import compute_digest, encode_v44_binding, verify_binding


def test_compute_and_verify_roundtrip() -> None:
    dek = bytes(32)
    policy = b"some-canonical-policy"
    binding = encode_v44_binding(dek, policy)
    res = verify_binding(binding, dek, policy)
    assert res.valid
    assert res.error_code is None


def test_tampered_binding_detected() -> None:
    dek = b"\x01" * 32
    policy = b"p1"
    binding = encode_v44_binding(dek, policy)
    res = verify_binding(binding, dek, b"p2")
    assert not res.valid
    assert res.error_code == ErrorCode.POLICY_BINDING_MISMATCH


def test_legacy_hex_then_base64_decoded() -> None:
    dek = b"\x02" * 32
    policy = b"legacy-policy"
    raw = compute_digest(dek, policy)
    legacy_hash = base64.b64encode(binascii.hexlify(raw)).decode("ascii")
    binding = {"alg": "HS256", "hash": legacy_hash}
    res = verify_binding(binding, dek, policy)
    assert res.valid
    assert res.detected_legacy_hex


def test_bare_string_binding_with_raw_digest() -> None:
    dek = b"\x03" * 32
    policy = b"bare-string-policy"
    binding = base64.b64encode(compute_digest(dek, policy)).decode("ascii")
    res = verify_binding(binding, dek, policy)
    assert res.valid
    assert not res.detected_legacy_hex


def test_unsupported_alg_rejected() -> None:
    dek = b"\x00" * 32
    policy = b"x"
    binding = {"alg": "HS512", "hash": base64.b64encode(b"\x00" * 32).decode("ascii")}
    res = verify_binding(binding, dek, policy)
    assert not res.valid
    assert res.error_code == ErrorCode.POLICY_BINDING_ALG_UNSUPPORTED

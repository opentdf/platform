"""Policy-binding compute and verify per BaseTDF-KAO §5.

Supports v4.4 object form, legacy bare-string form, and the legacy
hex-then-base64 inner encoding (BaseTDF-KAO §5.5, KAO-C-220, KAO-C-221).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from basetdf_kao.errors import ErrorCode

_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


@dataclass
class BindingResult:
    valid: bool
    error_code: ErrorCode | None = None
    detected_legacy_hex: bool = False
    canonical_digest: bytes | None = None


def compute_digest(dek_share: bytes, canonical_policy: bytes) -> bytes:
    """Raw HMAC-SHA256 digest per KAO-C-200/201."""
    return hmac.new(dek_share, canonical_policy, hashlib.sha256).digest()


def encode_v44_binding(dek_share: bytes, canonical_policy: bytes) -> dict[str, str]:
    digest = compute_digest(dek_share, canonical_policy)
    return {"alg": "HS256", "hash": base64.b64encode(digest).decode("ascii")}


def _normalize_stored_hash(stored_b64: str) -> tuple[bytes, bool]:
    """Decode a stored binding hash.

    Returns ``(raw_digest, detected_legacy_hex)``. When the first base64 decode
    yields 64 bytes that are entirely ASCII hex (KAO-C-220), the hex inner
    decoding is applied to recover the 32-byte HMAC digest.
    """
    decoded = base64.b64decode(stored_b64, validate=False)
    if len(decoded) == 64 and all(b in _HEX_DIGITS for b in decoded):
        try:
            return binascii.unhexlify(decoded), True
        except binascii.Error as e:
            raise ValueError(f"hex-decode failure on legacy binding: {e}") from e
    return decoded, False


def verify_binding(
    policy_binding: Any,
    dek_share: bytes,
    canonical_policy: bytes,
) -> BindingResult:
    """Verify a policy binding from a KAO against the canonical policy.

    `policy_binding` is the raw value from the KAO: object ``{alg, hash}`` or
    bare string. Constant-time comparison via ``hmac.compare_digest``.
    """
    if isinstance(policy_binding, dict):
        alg = policy_binding.get("alg")
        if alg != "HS256":
            return BindingResult(False, ErrorCode.POLICY_BINDING_ALG_UNSUPPORTED)
        stored_b64 = policy_binding.get("hash")
    elif isinstance(policy_binding, str):
        stored_b64 = policy_binding
    elif policy_binding is None:
        return BindingResult(False, ErrorCode.POLICY_BINDING_MISSING)
    else:
        return BindingResult(False, ErrorCode.POLICY_BINDING_FORMAT_INVALID)

    if not isinstance(stored_b64, str):
        return BindingResult(False, ErrorCode.POLICY_BINDING_FORMAT_INVALID)

    try:
        stored_digest, legacy = _normalize_stored_hash(stored_b64)
    except (binascii.Error, ValueError):
        return BindingResult(False, ErrorCode.LEGACY_DECODING_FAILURE)

    if len(stored_digest) != 32:
        return BindingResult(False, ErrorCode.POLICY_BINDING_FORMAT_INVALID, legacy)

    expected = compute_digest(dek_share, canonical_policy)
    if hmac.compare_digest(expected, stored_digest):
        return BindingResult(True, None, legacy, expected)
    return BindingResult(False, ErrorCode.POLICY_BINDING_MISMATCH, legacy, expected)

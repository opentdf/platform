"""Stable error codes from BaseTDF-KAO-CONF §3.

The values here MUST stay in lockstep with the error taxonomy table in
spec/basetdf/basetdf-kao-conformance.md and the TypeScript const in
spec/tools/explorer/src/data/errors.ts. CI parses the markdown table and
diffs all three.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    SCHEMA_VIOLATION = "kao.schema_violation"
    MISSING_REQUIRED_FIELD = "kao.missing_required_field"
    UNKNOWN_ALG = "kao.unknown_alg"
    ALG_TYPE_CONFLICT = "kao.alg_type_conflict"
    ALIAS_CONFLICT = "kao.alias_conflict"
    EPHEMERAL_KEY_REQUIRED = "kao.ephemeral_key_required"
    EPHEMERAL_KEY_UNEXPECTED = "kao.ephemeral_key_unexpected"
    POLICY_BINDING_MISSING = "kao.policy_binding_missing"
    POLICY_BINDING_FORMAT_INVALID = "kao.policy_binding_format_invalid"
    POLICY_BINDING_ALG_UNSUPPORTED = "kao.policy_binding_alg_unsupported"
    POLICY_BINDING_MISMATCH = "kao.policy_binding_mismatch"
    LEGACY_DECODING_FAILURE = "kao.legacy_decoding_failure"
    AEAD_TAG_FAILURE = "kao.aead_tag_failure"
    KEM_DECAPSULATION_FAILURE = "kao.kem_decapsulation_failure"
    METADATA_DECRYPT_FAILURE = "kao.metadata_decrypt_failure"
    METADATA_FORMAT_INVALID = "kao.metadata_format_invalid"
    SPLIT_RECONSTRUCTION_FAILURE = "kao.split_reconstruction_failure"

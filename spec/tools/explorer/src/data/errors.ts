// MUST stay in lockstep with:
//   - spec/basetdf/basetdf-kao-conformance.md §3
//   - spec/tools/python/src/basetdf_kao/errors.py (Python StrEnum)
// CI verifies parity.

export const ERROR_CODES = [
  "kao.schema_violation",
  "kao.missing_required_field",
  "kao.unknown_alg",
  "kao.alg_type_conflict",
  "kao.alias_conflict",
  "kao.ephemeral_key_required",
  "kao.ephemeral_key_unexpected",
  "kao.policy_binding_missing",
  "kao.policy_binding_format_invalid",
  "kao.policy_binding_alg_unsupported",
  "kao.policy_binding_mismatch",
  "kao.legacy_decoding_failure",
  "kao.aead_tag_failure",
  "kao.kem_decapsulation_failure",
  "kao.metadata_decrypt_failure",
  "kao.metadata_format_invalid",
  "kao.split_reconstruction_failure",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export const ERROR_DOCS: Record<ErrorCode, string> = {
  "kao.schema_violation":
    "JSON Schema validation fails and no more specific code applies.",
  "kao.missing_required_field":
    "A REQUIRED field (or its alias) is absent.",
  "kao.unknown_alg":
    "The alg value is not in the BaseTDF-ALG key-protection enum.",
  "kao.alg_type_conflict":
    "Both alg and type are present and do not agree per BaseTDF-KAO §7.1.",
  "kao.alias_conflict":
    "A v4.4 canonical field and its v4.3 alias are both present with different values.",
  "kao.ephemeral_key_required":
    "The algorithm requires ephemeralKey (key agreement / KEM / hybrid) and the field is absent.",
  "kao.ephemeral_key_unexpected":
    "The algorithm forbids ephemeralKey (RSA wrapping) and the field is present. Warning-level by default.",
  "kao.policy_binding_missing": "policyBinding is absent.",
  "kao.policy_binding_format_invalid":
    "policyBinding is neither a valid object nor a valid bare string.",
  "kao.policy_binding_alg_unsupported":
    "policyBinding.alg is present and is not 'HS256'.",
  "kao.policy_binding_mismatch":
    "After format normalization (including legacy hex-then-base64 detection), HMAC verification fails.",
  "kao.legacy_decoding_failure":
    "The hex-then-base64 detection rule produced an unexpected length after decoding.",
  "kao.aead_tag_failure":
    "AES-GCM authentication tag verification failed when unwrapping protectedKey.",
  "kao.kem_decapsulation_failure":
    "ML-KEM decapsulation rejected the supplied ciphertext.",
  "kao.metadata_decrypt_failure":
    "AES-GCM tag verification failed on encryptedMetadata.",
  "kao.metadata_format_invalid":
    "Decrypted encryptedMetadata is not valid JSON or lacks the documented shape.",
  "kao.split_reconstruction_failure":
    "XOR of recovered shares does not match the expected DEK length, or the reconstructed DEK does not produce a valid AES-GCM tag on the payload.",
};

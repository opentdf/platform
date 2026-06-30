"""Pydantic models for the Key Access Object.

The model accepts both v4.4 canonical fields and v4.3 aliases. `KAO.normalized()`
returns a v4.4-shape dict with aliases resolved per BaseTDF-KAO §7.1 and the
alias-precedence assertions in BaseTDF-KAO-CONF §4.3.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

CANONICAL_ALGORITHMS = {
    "RSA-OAEP",
    "RSA-OAEP-256",
    "ECDH-HKDF",
    "ML-KEM-768",
    "ML-KEM-1024",
    "X-ECDH-ML-KEM-768",
}

# v4.3 type → v4.4 alg mapping (BaseTDF-KAO §7.1).
TYPE_TO_ALG: dict[str, str] = {
    "wrapped": "RSA-OAEP",
    "ec-wrapped": "ECDH-HKDF",
}

# Inverse for KAO-C-303 (write SHOULD include `type`).
ALG_TO_TYPE: dict[str, str] = {
    "RSA-OAEP": "wrapped",
    "RSA-OAEP-256": "wrapped",
    "ECDH-HKDF": "ec-wrapped",
}


class AlgorithmCategory(StrEnum):
    WRAPPING = "wrapping"
    AGREEMENT = "agreement"
    ENCAPSULATION = "encapsulation"
    HYBRID = "hybrid"


_ALGORITHM_CATEGORY: dict[str, AlgorithmCategory] = {
    "RSA-OAEP": AlgorithmCategory.WRAPPING,
    "RSA-OAEP-256": AlgorithmCategory.WRAPPING,
    "ECDH-HKDF": AlgorithmCategory.AGREEMENT,
    "ML-KEM-768": AlgorithmCategory.ENCAPSULATION,
    "ML-KEM-1024": AlgorithmCategory.ENCAPSULATION,
    "X-ECDH-ML-KEM-768": AlgorithmCategory.HYBRID,
}


def algorithm_category(alg: str) -> AlgorithmCategory | None:
    return _ALGORITHM_CATEGORY.get(alg)


class PolicyBinding(BaseModel):
    """Object-form policy binding. Bare-string forms are normalized into this.

    `alg` is left as ``str`` so unsupported values reach the structural
    validator (which surfaces them as ``kao.policy_binding_alg_unsupported``)
    instead of being absorbed by the bare-string fallback in
    ``Union[PolicyBinding, str]``.
    """

    model_config = ConfigDict(extra="forbid")

    alg: str
    hash: str


class KAO(BaseModel):
    """KAO model accepting v4.4 canonical fields and v4.3 aliases.

    Use `KAO.from_obj(d)` to parse loosely-typed JSON. Use `KAO.normalized()`
    to produce the v4.4-shape dict with aliases resolved.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    alg: str | None = None
    type: str | None = None
    kas: str | None = None
    url: str | None = None
    kid: str | None = None
    sid: str | None = None
    protected_key: str | None = Field(default=None, alias="protectedKey")
    wrapped_key: str | None = Field(default=None, alias="wrappedKey")
    ephemeral_key: str | None = Field(default=None, alias="ephemeralKey")
    ephemeral_public_key: str | None = Field(default=None, alias="ephemeralPublicKey")
    policy_binding: PolicyBinding | str | None = Field(default=None, alias="policyBinding")
    encrypted_metadata: str | None = Field(default=None, alias="encryptedMetadata")
    protocol: str | None = None
    schema_version: str | None = Field(default=None, alias="schemaVersion")

    @classmethod
    def from_obj(cls, obj: Any) -> KAO:
        return cls.model_validate(obj)

    def resolved_algorithm(self) -> str | None:
        """Resolve the effective algorithm per BaseTDF-KAO §7.1.

        Returns the canonical v4.4 algorithm identifier, inferring from `type`
        when only `type` is present. Returns None when neither is present.
        """
        if self.alg is not None:
            return self.alg
        if self.type is not None:
            return TYPE_TO_ALG.get(self.type)
        return None

    def resolved_kas(self) -> str | None:
        return self.kas if self.kas is not None else self.url

    def resolved_protected_key(self) -> str | None:
        return self.protected_key if self.protected_key is not None else self.wrapped_key

    def resolved_ephemeral_key(self) -> str | None:
        return self.ephemeral_key if self.ephemeral_key is not None else self.ephemeral_public_key

    def normalized(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if (alg := self.resolved_algorithm()) is not None:
            out["alg"] = alg
        if (kas := self.resolved_kas()) is not None:
            out["kas"] = kas
        if self.kid is not None:
            out["kid"] = self.kid
        if self.sid is not None:
            out["sid"] = self.sid
        if (pk := self.resolved_protected_key()) is not None:
            out["protectedKey"] = pk
        if (ek := self.resolved_ephemeral_key()) is not None:
            out["ephemeralKey"] = ek
        if isinstance(self.policy_binding, PolicyBinding):
            out["policyBinding"] = self.policy_binding.model_dump()
        elif isinstance(self.policy_binding, str):
            # bare-string form normalizes to HS256 object (KAO-C-221)
            out["policyBinding"] = {"alg": "HS256", "hash": self.policy_binding}
        if self.encrypted_metadata is not None:
            out["encryptedMetadata"] = self.encrypted_metadata
        return out

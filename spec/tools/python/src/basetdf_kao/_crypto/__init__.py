"""Algorithm-specific protect/unprotect operations for the KAO.

WARNING — non-production code. This package validates the spec; production
TDF clients and KAS implementations live in `sdk/` and `service/`. Do not
import from this package in production paths.

Each submodule exposes:

  - protect(public_key, dek_share) -> ProtectResult(protected_key, ephemeral_key)
  - unprotect(private_key, protected_key, ephemeral_key) -> dek_share

ML-KEM-related operations are gated behind the `pqc` extra. Importing them
without `kyber-py` installed raises a clear error message.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProtectResult:
    protected_key: bytes
    ephemeral_key: bytes | None

"""ML-KEM-768 / ML-KEM-1024 key encapsulation (BaseTDF-KAO §4.3).

Lazy-imports `kyber-py`; raises a clear error if the `pqc` extra is missing.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from basetdf_kao._crypto import ProtectResult

HKDF_INFO_KEM = b"BaseTDF-KEM"


def _import_mlkem(alg: str) -> Any:
    """Import the appropriate ML-KEM scheme from kyber-py.

    `kyber-py` packages ML-KEM under `kyber_py.ml_kem.ML_KEM_{768,1024}`.
    """
    try:
        from kyber_py import ml_kem  # type: ignore[import-untyped]
    except ImportError as e:
        raise ImportError(
            "ML-KEM operations require the 'pqc' extra: pip install basetdf-kao[pqc]"
        ) from e
    if alg == "ML-KEM-768":
        return ml_kem.ML_KEM_768
    if alg == "ML-KEM-1024":
        return ml_kem.ML_KEM_1024
    raise ValueError(f"unsupported ML-KEM alg: {alg!r}")


def _derive_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=HKDF_INFO_KEM,
    ).derive(shared_secret)


def protect(
    alg: str,
    encapsulation_key: bytes,
    dek_share: bytes,
    *,
    iv: bytes,
    encap_seed: bytes | None = None,
) -> ProtectResult:
    scheme = _import_mlkem(alg)
    if encap_seed is not None:
        scheme.set_drbg_seed(encap_seed)
    ss, ct = scheme.encaps(encapsulation_key)
    derived = _derive_key(ss)
    ct_with_tag = AESGCM(derived).encrypt(iv, dek_share, associated_data=None)
    return ProtectResult(protected_key=iv + ct_with_tag, ephemeral_key=ct)


def unprotect(
    alg: str,
    decapsulation_key: bytes,
    protected_key: bytes,
    kem_ciphertext: bytes,
    *,
    iv_length: int = 12,
) -> bytes:
    scheme = _import_mlkem(alg)
    ss = scheme.decaps(decapsulation_key, kem_ciphertext)
    derived = _derive_key(ss)
    iv = protected_key[:iv_length]
    ct_with_tag = protected_key[iv_length:]
    return AESGCM(derived).decrypt(iv, ct_with_tag, associated_data=None)

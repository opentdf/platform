"""RSA-OAEP and RSA-OAEP-256 (BaseTDF-KAO §4.1)."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from basetdf_kao._crypto import ProtectResult


def _hash_for(alg: str) -> hashes.HashAlgorithm:
    if alg == "RSA-OAEP":
        return hashes.SHA1()
    if alg == "RSA-OAEP-256":
        return hashes.SHA256()
    raise ValueError(f"unsupported RSA alg: {alg!r}")


def protect(alg: str, public_key: rsa.RSAPublicKey, dek_share: bytes) -> ProtectResult:
    h = _hash_for(alg)
    ct = public_key.encrypt(
        dek_share,
        padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None),
    )
    return ProtectResult(protected_key=ct, ephemeral_key=None)


def unprotect(alg: str, private_key: rsa.RSAPrivateKey, protected_key: bytes) -> bytes:
    h = _hash_for(alg)
    return private_key.decrypt(
        protected_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=h), algorithm=h, label=None),
    )

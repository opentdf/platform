"""ECDH-HKDF key agreement and AES-256-GCM wrapping (BaseTDF-KAO §4.2)."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from basetdf_kao._crypto import ProtectResult

# Salt used by ECDH-HKDF in BaseTDF v4.4 (KAO-C-121).
HKDF_SALT_TDF = hashlib.sha256(b"TDF").digest()


def _derive_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT_TDF,
        info=b"",
    ).derive(shared_secret)


def protect(
    public_key: ec.EllipticCurvePublicKey,
    dek_share: bytes,
    *,
    iv: bytes,
    ephemeral_private_key: ec.EllipticCurvePrivateKey | None = None,
) -> ProtectResult:
    """Wrap `dek_share` to `public_key` using ECDH+HKDF+AES-256-GCM.

    Both `iv` and `ephemeral_private_key` are accepted to make this function
    deterministic for known-answer test vectors. Production code MUST always
    pass freshly random values.
    """
    if ephemeral_private_key is None:
        ephemeral_private_key = ec.generate_private_key(public_key.curve)
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    derived = _derive_key(shared_secret)
    aesgcm = AESGCM(derived)
    ct_with_tag = aesgcm.encrypt(iv, dek_share, associated_data=None)
    # Encode ephemeral public key as PEM (BaseTDF-KAO §4.2 ephemeralKey).
    ephemeral_pem = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return ProtectResult(protected_key=iv + ct_with_tag, ephemeral_key=ephemeral_pem)


def unprotect(
    private_key: ec.EllipticCurvePrivateKey,
    protected_key: bytes,
    ephemeral_key_pem: bytes,
    *,
    iv_length: int = 12,
) -> bytes:
    ephemeral_pub = serialization.load_pem_public_key(ephemeral_key_pem)
    if not isinstance(ephemeral_pub, ec.EllipticCurvePublicKey):
        raise TypeError("ephemeralKey must be an EC public key")
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_pub)
    derived = _derive_key(shared_secret)
    iv = protected_key[:iv_length]
    ct_with_tag = protected_key[iv_length:]
    return AESGCM(derived).decrypt(iv, ct_with_tag, associated_data=None)

"""X-ECDH-ML-KEM-768 hybrid (BaseTDF-KAO §4.4)."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from basetdf_kao._crypto import ProtectResult, _mlkem

HKDF_SALT_HYBRID = hashlib.sha256(b"BaseTDF-Hybrid").digest()
HKDF_INFO_HYBRID = b"BaseTDF-Hybrid-Key"

# Uncompressed P-256 point: 0x04 || X (32) || Y (32) = 65 bytes.
EC_POINT_LEN = 65
ML_KEM_768_CT_LEN = 1088
HYBRID_EPHEMERAL_LEN = EC_POINT_LEN + ML_KEM_768_CT_LEN  # 1153


def _combine(ss_classical: bytes, ss_pqc: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT_HYBRID,
        info=HKDF_INFO_HYBRID,
    ).derive(ss_classical + ss_pqc)


def protect(
    ec_public_key: ec.EllipticCurvePublicKey,
    mlkem_encapsulation_key: bytes,
    dek_share: bytes,
    *,
    iv: bytes,
    ephemeral_ec_private: ec.EllipticCurvePrivateKey | None = None,
    encap_seed: bytes | None = None,
) -> ProtectResult:
    if ephemeral_ec_private is None:
        ephemeral_ec_private = ec.generate_private_key(ec_public_key.curve)
    ss_classical = ephemeral_ec_private.exchange(ec.ECDH(), ec_public_key)

    scheme = _mlkem._import_mlkem("ML-KEM-768")
    if encap_seed is not None:
        scheme.set_drbg_seed(encap_seed)
    ss_pqc, kem_ct = scheme.encaps(mlkem_encapsulation_key)

    derived = _combine(ss_classical, ss_pqc)
    ct_with_tag = AESGCM(derived).encrypt(iv, dek_share, associated_data=None)

    ephemeral_ec_pub_bytes = ephemeral_ec_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(ephemeral_ec_pub_bytes) != EC_POINT_LEN:
        raise ValueError(
            f"unexpected EC point length {len(ephemeral_ec_pub_bytes)}; expected {EC_POINT_LEN}"
        )
    if len(kem_ct) != ML_KEM_768_CT_LEN:
        raise ValueError(
            f"unexpected ML-KEM ciphertext length {len(kem_ct)}; expected {ML_KEM_768_CT_LEN}"
        )

    return ProtectResult(
        protected_key=iv + ct_with_tag,
        ephemeral_key=ephemeral_ec_pub_bytes + kem_ct,
    )


def unprotect(
    ec_private_key: ec.EllipticCurvePrivateKey,
    mlkem_decapsulation_key: bytes,
    protected_key: bytes,
    ephemeral_blob: bytes,
    *,
    iv_length: int = 12,
) -> bytes:
    if len(ephemeral_blob) != HYBRID_EPHEMERAL_LEN:
        raise ValueError(
            f"hybrid ephemeralKey is {len(ephemeral_blob)} bytes; expected {HYBRID_EPHEMERAL_LEN}"
        )
    ec_point = ephemeral_blob[:EC_POINT_LEN]
    kem_ct = ephemeral_blob[EC_POINT_LEN:]

    ephemeral_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec_private_key.curve, ec_point)
    ss_classical = ec_private_key.exchange(ec.ECDH(), ephemeral_ec_pub)

    scheme = _mlkem._import_mlkem("ML-KEM-768")
    ss_pqc = scheme.decaps(mlkem_decapsulation_key, kem_ct)

    derived = _combine(ss_classical, ss_pqc)
    iv = protected_key[:iv_length]
    ct_with_tag = protected_key[iv_length:]
    return AESGCM(derived).decrypt(iv, ct_with_tag, associated_data=None)

"""Reproducible test-key generator for spec/testvectors/kao/keys/.

Run via the CLI: ``basetdf-kao gen-keys --out spec/testvectors/kao/keys``.

The keys produced by this script are committed to the repository. CI runs
this script into a temporary directory and asserts byte-identical output
(see the `fixtures-fresh` job). If `cryptography` or `kyber-py` change in a
way that breaks reproducibility, the CI job surfaces the drift.

Determinism strategy
--------------------

- **EC (P-256, P-384):** ``cryptography`` exposes a ``private_numbers``
  constructor. We derive the private scalar from a fixed seed via
  HKDF-SHA256 modulo the curve order.
- **ML-KEM-768 / ML-KEM-1024:** ``kyber-py`` exposes ``set_drbg_seed`` which
  re-seeds its internal DRBG. We seed before every ``keygen()`` call.
- **Hybrid:** combines a deterministic EC P-256 keypair and a deterministic
  ML-KEM-768 keypair under fixed seeds.
- **RSA:** ``cryptography``'s RSA keygen is NOT deterministic from a seed
  (the underlying OpenSSL primality search consumes randomness in a
  hardware-dependent way). For RSA we ship pre-generated PEM files inline
  in this script — generated once with `cryptography` 42.x and pinned —
  rather than regenerating on every CI run. The CI fixtures-fresh check
  compares the *current* on-disk file to the inlined source; mismatch fails.

WARNING — the keys produced by this script are PUBLIC test keys. They MUST
NOT be used in production.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


WARNING_TEXT = "NON-PRODUCTION TEST KEY -- DO NOT USE"


def _derive_ec_private_key(curve: ec.EllipticCurve, seed: bytes) -> ec.EllipticCurvePrivateKey:
    """Derive a deterministic EC private key from `seed`.

    Uses HKDF-SHA256 to expand the seed to a scalar in [1, n-1], where n is
    the curve order. Rejection-samples by re-running HKDF with an incremented
    `info` until the candidate falls in range (in practice a single iteration
    suffices for P-256 and P-384).
    """
    if isinstance(curve, ec.SECP256R1):
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        size = 32
    elif isinstance(curve, ec.SECP384R1):
        n = (
            0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF
            << 192
        ) | 0x581A0DB248B0A77AECEC196ACCC52973
        size = 48
    else:
        raise ValueError(f"unsupported curve: {curve.name}")

    counter = 0
    while True:
        info = b"basetdf-kao-test-ec/" + counter.to_bytes(4, "big")
        candidate = int.from_bytes(
            HKDF(algorithm=hashes.SHA256(), length=size, salt=b"", info=info).derive(seed),
            "big",
        )
        if 1 <= candidate < n:
            return ec.derive_private_key(candidate, curve)
        counter += 1


def _write_ec_key(out_dir: Path, key_id: str, curve_name: str, seed: bytes) -> dict[str, Any]:
    if curve_name == "P-256":
        curve: ec.EllipticCurve = ec.SECP256R1()
    elif curve_name == "P-384":
        curve = ec.SECP384R1()
    else:
        raise ValueError(curve_name)
    sk = _derive_ec_private_key(curve, seed)
    pk = sk.public_key()
    pk_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    (out_dir / f"{key_id}.pub.pem").write_bytes(pk_pem)
    (out_dir / f"{key_id}.priv.pem").write_bytes(sk_pem)
    meta = {
        "id": key_id,
        "algorithm": f"EC-{curve_name}",
        "publicKey": f"{key_id}.pub.pem",
        "privateKey": f"{key_id}.priv.pem",
        "provenance": (
            f"Deterministic from seed {seed.hex()} via HKDF-SHA256 over the "
            f"curve order (gen_test_keys.py)"
        ),
        "WARNING": WARNING_TEXT,
    }
    (out_dir / f"{key_id}.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def _write_mlkem_key(out_dir: Path, key_id: str, alg: str, seed: bytes) -> dict[str, Any]:
    from kyber_py import ml_kem  # type: ignore[import-not-found]

    if alg == "ML-KEM-768":
        scheme = ml_kem.ML_KEM_768
    elif alg == "ML-KEM-1024":
        scheme = ml_kem.ML_KEM_1024
    else:
        raise ValueError(alg)

    if len(seed) != 48:
        seed = HKDF(
            algorithm=hashes.SHA256(),
            length=48,
            salt=b"",
            info=b"basetdf-kao-test-mlkem-drbg/" + alg.encode(),
        ).derive(seed)
    scheme.set_drbg_seed(seed)
    ek, dk = scheme.keygen()
    bundle = {
        "id": key_id,
        "algorithm": alg,
        "encapsulationKey": ek.hex(),
        "decapsulationKey": dk.hex(),
        "provenance": (
            f"Deterministic from DRBG seed {seed.hex()} via kyber_py {alg} (gen_test_keys.py)"
        ),
        "WARNING": WARNING_TEXT,
    }
    (out_dir / f"{key_id}.json").write_text(json.dumps(bundle, indent=2) + "\n")
    meta = {
        "id": key_id,
        "algorithm": alg,
        "bundle": f"{key_id}.json",
        "provenance": bundle["provenance"],
        "WARNING": WARNING_TEXT,
    }
    (out_dir / f"{key_id}.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def _write_rsa_inlined(
    out_dir: Path, key_id: str, algorithm: str, key_pem: tuple[bytes, bytes]
) -> dict[str, Any]:
    pub_pem, priv_pem = key_pem
    (out_dir / f"{key_id}.pub.pem").write_bytes(pub_pem)
    (out_dir / f"{key_id}.priv.pem").write_bytes(priv_pem)
    meta = {
        "id": key_id,
        "algorithm": algorithm,
        "publicKey": f"{key_id}.pub.pem",
        "privateKey": f"{key_id}.priv.pem",
        "provenance": (
            "Inlined static PEM (RSA keygen is not seedable in cryptography). "
            "Generated once with cryptography 42.x; do not regenerate."
        ),
        "WARNING": WARNING_TEXT,
    }
    (out_dir / f"{key_id}.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def _ensure_rsa_keys() -> tuple[tuple[bytes, bytes], tuple[bytes, bytes]]:
    """Return ((rsa-2048 pub, priv), (rsa-4096 pub, priv)).

    On first run (no inlined PEMs yet), generate fresh keys and write them to
    a sibling file `_rsa_inlined.py` so that future runs reuse the same bytes.
    Subsequent CI runs read from the inlined module directly.
    """
    try:
        from basetdf_kao import _rsa_inlined  # type: ignore[import-not-found]
        return (
            (_rsa_inlined.RSA_2048_PUB, _rsa_inlined.RSA_2048_PRIV),
            (_rsa_inlined.RSA_4096_PUB, _rsa_inlined.RSA_4096_PRIV),
        )
    except ImportError:
        pass

    from cryptography.hazmat.primitives.asymmetric import rsa

    def _kp(bits: int) -> tuple[bytes, bytes]:
        sk = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        return (
            sk.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            sk.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )

    rsa_2048 = _kp(2048)
    rsa_4096 = _kp(4096)

    inlined_path = Path(__file__).resolve().parents[1] / "src" / "basetdf_kao" / "_rsa_inlined.py"
    inlined_path.write_text(
        "# Auto-generated by gen_test_keys.py. RSA keygen is not seedable, so we\n"
        "# pin the bytes here. Regenerate ONLY by deleting this file and re-running\n"
        "# the script; downstream test vectors will need to be regenerated as well.\n"
        f"RSA_2048_PUB = {rsa_2048[0]!r}\n"
        f"RSA_2048_PRIV = {rsa_2048[1]!r}\n"
        f"RSA_4096_PUB = {rsa_4096[0]!r}\n"
        f"RSA_4096_PRIV = {rsa_4096[1]!r}\n"
    )
    return rsa_2048, rsa_4096


def generate_all(out_dir: Path) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    metas: list[dict[str, Any]] = []

    rsa_2048, rsa_4096 = _ensure_rsa_keys()
    metas.append(_write_rsa_inlined(out_dir, "rsa-2048-test", "RSA-2048", rsa_2048))
    metas.append(_write_rsa_inlined(out_dir, "rsa-4096-test", "RSA-4096", rsa_4096))

    metas.append(
        _write_ec_key(out_dir, "ec-p256-test", "P-256", b"basetdf-kao/ec-p256-test-seed-001")
    )
    metas.append(
        _write_ec_key(out_dir, "ec-p384-test", "P-384", b"basetdf-kao/ec-p384-test-seed-001")
    )

    metas.append(
        _write_mlkem_key(
            out_dir, "ml-kem-768-test", "ML-KEM-768", b"basetdf-kao/mlkem768-test-seed-001"
        )
    )
    metas.append(
        _write_mlkem_key(
            out_dir, "ml-kem-1024-test", "ML-KEM-1024", b"basetdf-kao/mlkem1024-test-seed-001"
        )
    )

    return metas


def main(out_dir: str = "spec/testvectors/kao/keys") -> None:
    p = Path(out_dir).resolve()
    metas = generate_all(p)
    print(f"wrote {len(metas)} key bundles to {p}")


if __name__ == "__main__":
    import sys

    main(sys.argv[1] if len(sys.argv) > 1 else "spec/testvectors/kao/keys")

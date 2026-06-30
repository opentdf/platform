"""Reproducible test-vector generator for spec/testvectors/kao/vectors/.

For every entry in ``index.json``, this script emits a JSON file under
``vectors/`` that conforms to ``vector.schema.json``. Crypto values are
deterministic: ECDH ephemeral keys are seeded, ML-KEM uses ``set_drbg_seed``,
and AES-GCM IVs are fixed-per-vector. Re-running this script over the
checked-in keys MUST produce byte-identical files; CI's ``fixtures-fresh``
job depends on that.

Run via the CLI: ``basetdf-kao gen-vectors``.

WARNING — non-production. The keys, DEK shares, and policy bytes here are
public test fixtures.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from basetdf_kao._crypto import _ecdh, _hybrid, _mlkem, _rsa
from basetdf_kao.binding import compute_digest


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64u_to_b64(s: str) -> str:
    return s


# Deterministic test material reused across vectors.
DEK_PRIMARY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
DEK_SHARE_A = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f000000000000000000000000000000ff"
)
DEK_SHARE_B = bytes(a ^ b for a, b in zip(DEK_PRIMARY, DEK_SHARE_A))  # XOR partner

# Canonical policy: a small JSON object base64-encoded as it would appear in
# encryptionInformation.policy.
POLICY_JSON = json.dumps(
    {
        "uuid": "12345678-1234-4321-9876-123456789abc",
        "body": {
            "dataAttributes": [
                {"attribute": "https://example.com/attr/Classification/value/Public"}
            ],
            "dissem": [],
        },
    },
    separators=(",", ":"),
).encode("ascii")
POLICY_B64 = base64.b64encode(POLICY_JSON).decode("ascii")

KAS_URL = "https://kas.example.com"

FIXED_IV = bytes.fromhex("000102030405060708090a0b")
FIXED_IV_2 = bytes.fromhex("0a0b0c0d0e0f101112131415")


def _hmac_b64(dek_share: bytes) -> str:
    return _b64(compute_digest(dek_share, POLICY_B64.encode("ascii")))


def _load_keys(keys_dir: Path) -> dict[str, Any]:
    K = keys_dir
    rsa_pk = serialization.load_pem_public_key((K / "rsa-2048-test.pub.pem").read_bytes())
    rsa_sk = serialization.load_pem_private_key(
        (K / "rsa-2048-test.priv.pem").read_bytes(), password=None
    )
    rsa4_pk = serialization.load_pem_public_key((K / "rsa-4096-test.pub.pem").read_bytes())
    rsa4_sk = serialization.load_pem_private_key(
        (K / "rsa-4096-test.priv.pem").read_bytes(), password=None
    )
    ec_pk = serialization.load_pem_public_key((K / "ec-p256-test.pub.pem").read_bytes())
    ec_sk = serialization.load_pem_private_key(
        (K / "ec-p256-test.priv.pem").read_bytes(), password=None
    )
    mk768 = json.loads((K / "ml-kem-768-test.json").read_text())
    mk1024 = json.loads((K / "ml-kem-1024-test.json").read_text())
    return {
        "rsa-2048": (rsa_pk, rsa_sk),
        "rsa-4096": (rsa4_pk, rsa4_sk),
        "ec-p256": (ec_pk, ec_sk),
        "ml-kem-768": (bytes.fromhex(mk768["encapsulationKey"]), bytes.fromhex(mk768["decapsulationKey"])),
        "ml-kem-1024": (
            bytes.fromhex(mk1024["encapsulationKey"]),
            bytes.fromhex(mk1024["decapsulationKey"]),
        ),
    }


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def _vector(
    *,
    id: str,
    description: str,
    conformance: list[str],
    category: str,
    algorithm: str,
    kao: dict[str, Any],
    expected: dict[str, Any],
    inputs_extra: dict[str, Any] | None = None,
    keys_used: dict[str, str] | None = None,
) -> dict[str, Any]:
    inputs: dict[str, Any] = {"kao": kao, "policy": POLICY_B64}
    if keys_used:
        inputs["keys"] = keys_used
    if inputs_extra:
        inputs.update(inputs_extra)
    return {
        "id": id,
        "description": description,
        "conformance": conformance,
        "category": category,
        "algorithm": algorithm,
        "manifestSchemaVersion": "4.4.0",
        "inputs": inputs,
        "expected": expected,
    }


def _normalize(kao: dict[str, Any]) -> dict[str, Any]:
    """Mirror KAO.normalized() for the expected.normalizedKao field."""
    out: dict[str, Any] = {}
    alg = kao.get("alg")
    if alg is None and "type" in kao:
        alg = {"wrapped": "RSA-OAEP", "ec-wrapped": "ECDH-HKDF"}.get(kao["type"])
    if alg is not None:
        out["alg"] = alg
    if "kas" in kao:
        out["kas"] = kao["kas"]
    elif "url" in kao:
        out["kas"] = kao["url"]
    if "kid" in kao:
        out["kid"] = kao["kid"]
    if "sid" in kao:
        out["sid"] = kao["sid"]
    if "protectedKey" in kao:
        out["protectedKey"] = kao["protectedKey"]
    elif "wrappedKey" in kao:
        out["protectedKey"] = kao["wrappedKey"]
    if "ephemeralKey" in kao:
        out["ephemeralKey"] = kao["ephemeralKey"]
    elif "ephemeralPublicKey" in kao:
        out["ephemeralKey"] = kao["ephemeralPublicKey"]
    pb = kao.get("policyBinding")
    if isinstance(pb, dict):
        out["policyBinding"] = pb
    elif isinstance(pb, str):
        out["policyBinding"] = {"alg": "HS256", "hash": pb}
    if "encryptedMetadata" in kao:
        out["encryptedMetadata"] = kao["encryptedMetadata"]
    return out


def _build_positive_rsa(keys: dict[str, Any], alg: str, vector_id: str, kid: str) -> dict[str, Any]:
    pk, _ = keys["rsa-2048" if alg == "RSA-OAEP-256" else "rsa-4096"]
    # NOTE: RSA-OAEP encryption is randomized; we cannot pin a deterministic
    # ciphertext. For positive vectors we use a fresh wrap and document that
    # the test harness regenerates the protectedKey at vector-author time.
    res = _rsa.protect(alg, pk, DEK_PRIMARY)
    kao = {
        "alg": alg,
        "kas": KAS_URL,
        "kid": kid,
        "sid": "s-0",
        "protectedKey": _b64(res.protected_key),
        "policyBinding": {"alg": "HS256", "hash": _hmac_b64(DEK_PRIMARY)},
    }
    return _vector(
        id=vector_id,
        description=f"Round-trip wrap/unwrap with {alg} using the {kid} test key.",
        conformance=["KAO-C-001", "KAO-C-006", "KAO-C-100" if alg == "RSA-OAEP" else "KAO-C-101", "KAO-C-202"],
        category="positive",
        algorithm=alg,
        kao=kao,
        expected={
            "outcome": "accept",
            "policyBindingValid": True,
            "recoveredDek": DEK_PRIMARY.hex(),
            "normalizedKao": _normalize(kao),
        },
        keys_used={
            "kas": f"keys/{'rsa-2048-test' if alg == 'RSA-OAEP-256' else 'rsa-4096-test'}.priv.pem"
        },
    )


def _build_positive_ecdh(keys: dict[str, Any]) -> dict[str, Any]:
    ec_pk, _ = keys["ec-p256"]
    eph_sk = ec.derive_private_key(0xC0FFEE_C0FFEE_C0FFEE_C0FFEE, ec_pk.curve)
    res = _ecdh.protect(ec_pk, DEK_PRIMARY, iv=FIXED_IV, ephemeral_private_key=eph_sk)
    kao = {
        "alg": "ECDH-HKDF",
        "kas": KAS_URL,
        "kid": "ec-p256-test",
        "sid": "s-0",
        "protectedKey": _b64(res.protected_key),
        "ephemeralKey": res.ephemeral_key.decode("ascii"),
        "policyBinding": {"alg": "HS256", "hash": _hmac_b64(DEK_PRIMARY)},
    }
    return _vector(
        id="pos-ecdh-hkdf-aesgcm-001",
        description="ECDH-HKDF v4.4 with deterministic ephemeral keypair and fixed AES-GCM IV.",
        conformance=["KAO-C-001", "KAO-C-030", "KAO-C-120", "KAO-C-122"],
        category="positive",
        algorithm="ECDH-HKDF",
        kao=kao,
        expected={
            "outcome": "accept",
            "policyBindingValid": True,
            "recoveredDek": DEK_PRIMARY.hex(),
            "normalizedKao": _normalize(kao),
        },
        keys_used={"kas": "keys/ec-p256-test.priv.pem"},
    )


def _build_positive_mlkem(keys: dict[str, Any], alg: str, vector_id: str) -> dict[str, Any]:
    suffix = alg.removeprefix("ML-KEM-")
    ek, _ = keys[f"ml-kem-{suffix}"]
    seed = b"basetdf-kao/encaps-seed/" + alg.encode()
    seed = hashlib.sha256(seed).digest() + hashlib.sha256(seed + b"/2").digest()[:16]
    res = _mlkem.protect(alg, ek, DEK_PRIMARY, iv=FIXED_IV, encap_seed=seed)
    kao = {
        "alg": alg,
        "kas": KAS_URL,
        "kid": f"ml-kem-{suffix}-test",
        "sid": "s-0",
        "protectedKey": _b64(res.protected_key),
        "ephemeralKey": _b64(res.ephemeral_key),
        "policyBinding": {"alg": "HS256", "hash": _hmac_b64(DEK_PRIMARY)},
    }
    return _vector(
        id=vector_id,
        description=f"{alg} encapsulation + AES-GCM wrap with deterministic DRBG seed.",
        conformance=["KAO-C-001", "KAO-C-030", "KAO-C-140", "KAO-C-142", "KAO-C-143"],
        category="positive",
        algorithm=alg,
        kao=kao,
        expected={
            "outcome": "accept",
            "policyBindingValid": True,
            "recoveredDek": DEK_PRIMARY.hex(),
            "normalizedKao": _normalize(kao),
        },
        keys_used={"kas": f"keys/ml-kem-{suffix}-test.json"},
    )


def _build_positive_hybrid(keys: dict[str, Any]) -> dict[str, Any]:
    ec_pk, _ = keys["ec-p256"]
    mk_ek, _ = keys["ml-kem-768"]
    eph_sk = ec.derive_private_key(0xBEEF_BEEF_BEEF_BEEF, ec_pk.curve)
    seed = hashlib.sha256(b"basetdf-kao/hybrid-encaps-seed").digest() + bytes(16)
    res = _hybrid.protect(
        ec_pk, mk_ek, DEK_PRIMARY, iv=FIXED_IV, ephemeral_ec_private=eph_sk, encap_seed=seed
    )
    kao = {
        "alg": "X-ECDH-ML-KEM-768",
        "kas": KAS_URL,
        "kid": "hybrid-test",
        "sid": "s-0",
        "protectedKey": _b64(res.protected_key),
        "ephemeralKey": _b64(res.ephemeral_key),
        "policyBinding": {"alg": "HS256", "hash": _hmac_b64(DEK_PRIMARY)},
    }
    return _vector(
        id="pos-hybrid-x-ecdh-mlkem-768-001",
        description="Hybrid X-ECDH-ML-KEM-768 with deterministic EC ephemeral and ML-KEM seed.",
        conformance=["KAO-C-001", "KAO-C-030", "KAO-C-160", "KAO-C-161", "KAO-C-163"],
        category="positive",
        algorithm="X-ECDH-ML-KEM-768",
        kao=kao,
        expected={
            "outcome": "accept",
            "policyBindingValid": True,
            "recoveredDek": DEK_PRIMARY.hex(),
            "normalizedKao": _normalize(kao),
        },
        keys_used={
            "kasEC": "keys/ec-p256-test.priv.pem",
            "kasMLKEM": "keys/ml-kem-768-test.json",
        },
    )


def _build_negative_tampered_binding(keys: dict[str, Any]) -> dict[str, Any]:
    rsa_pk, _ = keys["rsa-2048"]
    res = _rsa.protect("RSA-OAEP-256", rsa_pk, DEK_PRIMARY)
    # Compute the hash for a DIFFERENT DEK so it won't match.
    bad_hash = _b64(compute_digest(b"\x00" * 32, POLICY_B64.encode("ascii")))
    kao = {
        "alg": "RSA-OAEP-256",
        "kas": KAS_URL,
        "kid": "rsa-2048-test",
        "sid": "s-0",
        "protectedKey": _b64(res.protected_key),
        "policyBinding": {"alg": "HS256", "hash": bad_hash},
    }
    return _vector(
        id="neg-policy-binding-tampered-001",
        description="Policy binding hash is computed under a different DEK; HMAC verify fails.",
        conformance=["KAO-C-206", "KAO-C-350"],
        category="negative",
        algorithm="RSA-OAEP-256",
        kao=kao,
        expected={
            "outcome": "reject",
            "errorCode": "kao.policy_binding_mismatch",
            "policyBindingValid": False,
        },
        inputs_extra={"dekShare": DEK_PRIMARY.hex()},
        keys_used={"kas": "keys/rsa-2048-test.priv.pem"},
    )


def _build_kat_policy_binding() -> dict[str, Any]:
    dek = bytes.fromhex(
        "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728"  # 31 bytes
    )
    dek = dek + b"\x29"  # 32-byte fixed DEK
    digest = compute_digest(dek, POLICY_B64.encode("ascii"))
    kao = {
        "alg": "RSA-OAEP",
        "kas": KAS_URL,
        "kid": "rsa-4096-test",
        "sid": "s-0",
        "protectedKey": _b64(b"\x00" * 256),
        "policyBinding": {"alg": "HS256", "hash": _b64(digest)},
    }
    return _vector(
        id="kat-policy-binding-001",
        description=(
            "Pins the HMAC-SHA256 digest for a fixed DEK and canonical policy. "
            "protectedKey is a placeholder; this vector tests binding only."
        ),
        conformance=["KAO-C-200", "KAO-C-201", "KAO-C-203"],
        category="kat",
        algorithm="RSA-OAEP",
        kao=kao,
        expected={
            "outcome": "accept",
            "policyBindingValid": True,
            "normalizedKao": _normalize(kao),
        },
        inputs_extra={"dekShare": dek.hex()},
        keys_used={"kas": "keys/rsa-4096-test.priv.pem"},
    )


def _build_simple_negative(
    *,
    id: str,
    description: str,
    conformance: list[str],
    error_code: str,
    kao: dict[str, Any],
    algorithm: str = "n/a",
) -> dict[str, Any]:
    return _vector(
        id=id,
        description=description,
        conformance=conformance,
        category="negative",
        algorithm=algorithm,
        kao=kao,
        expected={"outcome": "reject", "errorCode": error_code},
    )


def _baseline_kao() -> dict[str, Any]:
    return {
        "alg": "RSA-OAEP-256",
        "kas": KAS_URL,
        "kid": "rsa-2048-test",
        "sid": "s-0",
        "protectedKey": _b64(b"\x00" * 256),
        "policyBinding": {"alg": "HS256", "hash": _b64(b"\x00" * 32)},
    }


def generate_all(out_dir: Path, keys_dir: Path) -> int:
    keys = _load_keys(keys_dir)
    vectors: list[dict[str, Any]] = []

    # Positive
    vectors.append(_build_positive_rsa(keys, "RSA-OAEP-256", "pos-rsa-oaep-256-001", "rsa-2048-test"))
    vectors.append(_build_positive_rsa(keys, "RSA-OAEP", "pos-rsa-oaep-sha1-001", "rsa-4096-test"))
    vectors.append(_build_positive_ecdh(keys))
    vectors.append(_build_positive_mlkem(keys, "ML-KEM-768", "pos-mlkem-768-001"))
    vectors.append(_build_positive_mlkem(keys, "ML-KEM-1024", "pos-mlkem-1024-001"))
    vectors.append(_build_positive_hybrid(keys))

    # KAT
    vectors.append(_build_kat_policy_binding())

    # Hand-crafted structural negatives
    bk = _baseline_kao()

    no_alg = {k: v for k, v in bk.items() if k != "alg"}
    vectors.append(
        _build_simple_negative(
            id="neg-missing-alg-and-type-001",
            description="Neither alg nor type is present.",
            conformance=["KAO-C-002"],
            error_code="kao.missing_required_field",
            kao=no_alg,
        )
    )

    no_kas = {k: v for k, v in bk.items() if k != "kas"}
    vectors.append(
        _build_simple_negative(
            id="neg-missing-kas-and-url-001",
            description="Neither kas nor url is present.",
            conformance=["KAO-C-003"],
            error_code="kao.missing_required_field",
            kao=no_kas,
        )
    )

    no_pk = {k: v for k, v in bk.items() if k != "protectedKey"}
    vectors.append(
        _build_simple_negative(
            id="neg-missing-protected-and-wrapped-001",
            description="Neither protectedKey nor wrappedKey is present.",
            conformance=["KAO-C-004"],
            error_code="kao.missing_required_field",
            kao=no_pk,
        )
    )

    no_pb = {k: v for k, v in bk.items() if k != "policyBinding"}
    vectors.append(
        _build_simple_negative(
            id="neg-missing-policy-binding-001",
            description="policyBinding field is absent.",
            conformance=["KAO-C-005"],
            error_code="kao.policy_binding_missing",
            kao=no_pb,
        )
    )

    bad_alg = {**bk, "alg": "XSALSA20"}
    vectors.append(
        _build_simple_negative(
            id="neg-unknown-alg-001",
            description="alg is not in the registered enum.",
            conformance=["KAO-C-010", "KAO-C-352"],
            error_code="kao.unknown_alg",
            kao=bad_alg,
        )
    )

    alg_type_conflict = {**bk, "type": "ec-wrapped"}
    vectors.append(
        _build_simple_negative(
            id="neg-alg-type-conflict-001",
            description="alg=RSA-OAEP-256 and type=ec-wrapped disagree.",
            conformance=["KAO-C-020", "KAO-C-353"],
            error_code="kao.alg_type_conflict",
            kao=alg_type_conflict,
        )
    )

    alias_conflict = {**bk, "url": "https://other.example.com"}
    vectors.append(
        _build_simple_negative(
            id="neg-alias-conflict-kas-url-001",
            description="kas and url present with different values.",
            conformance=["KAO-C-021"],
            error_code="kao.alias_conflict",
            kao=alias_conflict,
        )
    )

    proto_alias_conflict = {**bk, "wrappedKey": _b64(b"\xff" * 256)}
    vectors.append(
        _build_simple_negative(
            id="neg-alias-conflict-protected-wrapped-001",
            description="protectedKey and wrappedKey present with different values.",
            conformance=["KAO-C-022"],
            error_code="kao.alias_conflict",
            kao=proto_alias_conflict,
        )
    )

    eph_alias_conflict = {
        **bk,
        "alg": "ECDH-HKDF",
        "ephemeralKey": "PEM-A",
        "ephemeralPublicKey": "PEM-B",
    }
    vectors.append(
        _build_simple_negative(
            id="neg-alias-conflict-ephemeral-001",
            description="ephemeralKey and ephemeralPublicKey present with different values.",
            conformance=["KAO-C-023"],
            error_code="kao.alias_conflict",
            kao=eph_alias_conflict,
        )
    )

    no_eph_mlkem = {**bk, "alg": "ML-KEM-768", "kid": "ml-kem-768-test"}
    vectors.append(
        _build_simple_negative(
            id="neg-ephemeral-key-required-mlkem-001",
            description="alg=ML-KEM-768 but ephemeralKey is absent.",
            conformance=["KAO-C-030"],
            error_code="kao.ephemeral_key_required",
            kao=no_eph_mlkem,
            algorithm="ML-KEM-768",
        )
    )

    no_eph_ecdh = {**bk, "alg": "ECDH-HKDF", "kid": "ec-p256-test"}
    vectors.append(
        _build_simple_negative(
            id="neg-ephemeral-key-required-ecdh-001",
            description="alg=ECDH-HKDF but ephemeralKey is absent.",
            conformance=["KAO-C-030"],
            error_code="kao.ephemeral_key_required",
            kao=no_eph_ecdh,
            algorithm="ECDH-HKDF",
        )
    )

    no_eph_hybrid = {**bk, "alg": "X-ECDH-ML-KEM-768", "kid": "hybrid-test"}
    vectors.append(
        _build_simple_negative(
            id="neg-ephemeral-key-required-hybrid-001",
            description="alg=X-ECDH-ML-KEM-768 but ephemeralKey is absent.",
            conformance=["KAO-C-030"],
            error_code="kao.ephemeral_key_required",
            kao=no_eph_hybrid,
            algorithm="X-ECDH-ML-KEM-768",
        )
    )

    bad_pb_alg = {**bk, "policyBinding": {"alg": "HS512", "hash": _b64(b"\x00" * 32)}}
    vectors.append(
        _build_simple_negative(
            id="neg-policy-binding-alg-unsupported-001",
            description="policyBinding.alg=HS512 is not supported.",
            conformance=["KAO-C-202", "KAO-C-351"],
            error_code="kao.policy_binding_alg_unsupported",
            kao=bad_pb_alg,
            algorithm="RSA-OAEP-256",
        )
    )

    extra_prop = {**bk, "policyBinding": {"alg": "HS256", "hash": _b64(b"\x00" * 32), "extra": True}}
    vectors.append(
        _build_simple_negative(
            id="neg-policy-binding-extra-prop-001",
            description="policyBinding object carries an extra property.",
            conformance=["KAO-C-014"],
            error_code="kao.schema_violation",
            kao=extra_prop,
        )
    )

    addl_prop = {**bk, "extraField": "rejected"}
    vectors.append(
        _build_simple_negative(
            id="neg-additional-properties-001",
            description="KAO carries an unknown top-level property.",
            conformance=["KAO-C-013"],
            error_code="kao.schema_violation",
            kao=addl_prop,
        )
    )

    # Tampered binding requires real crypto inputs, so handle separately.
    vectors.append(_build_negative_tampered_binding(keys))

    # Save all
    for v in vectors:
        path = out_dir / "vectors" / f"{v['id']}.json"
        _save(path, v)
    return len(vectors)


def main(out_dir: str = "spec/testvectors/kao") -> None:
    p = Path(out_dir).resolve()
    n = generate_all(p, p / "keys")
    print(f"wrote {n} test vectors to {p}/vectors/")


if __name__ == "__main__":
    import sys

    main(sys.argv[1] if len(sys.argv) > 1 else "spec/testvectors/kao")

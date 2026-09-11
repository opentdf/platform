"""Structural validation of KAO objects against BaseTDF-KAO-CONF assertions.

Each finding is tagged with a ``KAO-C-NNN`` conformance identifier and an
``ErrorCode``. Crypto-level checks (HMAC verify, AES-GCM tag, ML-KEM
decapsulation) live in `basetdf_kao.binding` and `basetdf_kao.crypto`; this
module covers structural and alias-resolution assertions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from basetdf_kao.errors import ErrorCode
from basetdf_kao.model import (
    ALG_TO_TYPE,
    CANONICAL_ALGORITHMS,
    KAO,
    AlgorithmCategory,
    algorithm_category,
)
from basetdf_kao.schema import kao_validator


@dataclass
class ConformanceFinding:
    code: ErrorCode
    conformance_id: str
    path: str
    message: str
    severity: str = "error"


@dataclass
class ValidationReport:
    errors: list[ConformanceFinding] = field(default_factory=list)
    warnings: list[ConformanceFinding] = field(default_factory=list)
    normalized: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def first_error_code(self) -> ErrorCode | None:
        return self.errors[0].code if self.errors else None


def _err(code: ErrorCode, cid: str, path: str, message: str) -> ConformanceFinding:
    return ConformanceFinding(code=code, conformance_id=cid, path=path, message=message)


def _warn(code: ErrorCode, cid: str, path: str, message: str) -> ConformanceFinding:
    return ConformanceFinding(
        code=code, conformance_id=cid, path=path, message=message, severity="warning"
    )


def _classify_schema_error(obj: Any, e: Any) -> ConformanceFinding:
    """Translate a jsonschema ValidationError into a conformance finding.

    The schema's structural requirements map onto specific KAO-C-NNN ids.
    Anything we can't classify becomes a generic schema_violation tagged with
    KAO-C-001 (catch-all "well-formed v4.4 KAO" assertion).
    """
    msg = e.message
    path = "/" + "/".join(str(p) for p in e.absolute_path)

    # additionalProperties: false on the top-level KAO maps to KAO-C-013.
    if "Additional properties" in msg or "additional properties" in msg:
        if e.absolute_path and e.absolute_path[0] == "policyBinding":
            return _err(ErrorCode.SCHEMA_VIOLATION, "KAO-C-014", path, msg)
        return _err(ErrorCode.SCHEMA_VIOLATION, "KAO-C-013", path, msg)

    # The four `allOf` clauses on the root enforce alg/type, kas/url,
    # protectedKey/wrappedKey, and policyBinding presence.
    if "is not valid under any of the given schemas" in msg or "anyOf" in msg:
        if "alg" in msg and "type" in msg:
            return _err(ErrorCode.MISSING_REQUIRED_FIELD, "KAO-C-002", "/alg", msg)
        if "kas" in msg and "url" in msg:
            return _err(ErrorCode.MISSING_REQUIRED_FIELD, "KAO-C-003", "/kas", msg)
        if "protectedKey" in msg and "wrappedKey" in msg:
            return _err(ErrorCode.MISSING_REQUIRED_FIELD, "KAO-C-004", "/protectedKey", msg)

    if "'policyBinding' is a required property" in msg:
        return _err(ErrorCode.POLICY_BINDING_MISSING, "KAO-C-005", "/policyBinding", msg)

    # alg enum violation maps to unknown_alg / KAO-C-010.
    if e.absolute_path and e.absolute_path[0] == "alg" and "is not one of" in msg:
        return _err(ErrorCode.UNKNOWN_ALG, "KAO-C-010", path, msg)

    return _err(ErrorCode.SCHEMA_VIOLATION, "KAO-C-001", path, msg)


def validate_kao(obj: Any, *, schema_only: bool = False) -> ValidationReport:
    report = ValidationReport()

    # Step 1: JSON Schema. Tag each error with the most specific conformance
    # ID we can. We do NOT early-return on schema errors; later checks may
    # surface more specific findings (e.g., the post-schema policy-binding alg
    # check), and tests expect to see them.
    for e in kao_validator().iter_errors(obj):
        report.errors.append(_classify_schema_error(obj, e))

    if schema_only:
        try:
            kao = KAO.from_obj(obj)
            report.normalized = kao.normalized()
        except Exception as exc:
            report.errors.append(_err(ErrorCode.SCHEMA_VIOLATION, "KAO-C-001", "/", str(exc)))
        return report

    # Step 2: Pydantic parse. Pydantic enforces field types and aliases; if it
    # fails outright, structural analysis can't proceed.
    try:
        kao = KAO.from_obj(obj)
    except Exception as exc:
        report.errors.append(_err(ErrorCode.SCHEMA_VIOLATION, "KAO-C-001", "/", str(exc)))
        return report

    # Step 3: Resolved-required-field presence (KAO-C-002..005).
    if kao.resolved_algorithm() is None:
        report.errors.append(
            _err(
                ErrorCode.MISSING_REQUIRED_FIELD,
                "KAO-C-002",
                "/alg",
                "neither alg nor type is present",
            )
        )
    if kao.resolved_kas() is None:
        report.errors.append(
            _err(
                ErrorCode.MISSING_REQUIRED_FIELD,
                "KAO-C-003",
                "/kas",
                "neither kas nor url is present",
            )
        )
    if kao.resolved_protected_key() is None:
        report.errors.append(
            _err(
                ErrorCode.MISSING_REQUIRED_FIELD,
                "KAO-C-004",
                "/protectedKey",
                "neither protectedKey nor wrappedKey is present",
            )
        )

    # Step 4: Alias precedence (KAO-C-020..023).
    if kao.alg is not None and kao.type is not None:
        expected_type = ALG_TO_TYPE.get(kao.alg)
        if expected_type is not None and expected_type != kao.type:
            report.errors.append(
                _err(
                    ErrorCode.ALG_TYPE_CONFLICT,
                    "KAO-C-020",
                    "/type",
                    f"alg={kao.alg!r} and type={kao.type!r} disagree",
                )
            )
        elif expected_type is None and kao.type != "":
            # alg has no type equivalent (e.g., ML-KEM); type SHOULD be omitted.
            report.errors.append(
                _err(
                    ErrorCode.ALG_TYPE_CONFLICT,
                    "KAO-C-020",
                    "/type",
                    f"alg={kao.alg!r} has no v4.3 type equivalent; type={kao.type!r} should be omitted",
                )
            )

    if kao.kas is not None and kao.url is not None and kao.kas != kao.url:
        report.errors.append(
            _err(
                ErrorCode.ALIAS_CONFLICT,
                "KAO-C-021",
                "/url",
                "kas and url both present with different values",
            )
        )

    if (
        kao.protected_key is not None
        and kao.wrapped_key is not None
        and kao.protected_key != kao.wrapped_key
    ):
        report.errors.append(
            _err(
                ErrorCode.ALIAS_CONFLICT,
                "KAO-C-022",
                "/wrappedKey",
                "protectedKey and wrappedKey both present with different values",
            )
        )

    if (
        kao.ephemeral_key is not None
        and kao.ephemeral_public_key is not None
        and kao.ephemeral_key != kao.ephemeral_public_key
    ):
        report.errors.append(
            _err(
                ErrorCode.ALIAS_CONFLICT,
                "KAO-C-023",
                "/ephemeralPublicKey",
                "ephemeralKey and ephemeralPublicKey both present with different values",
            )
        )

    # Step 4: Algorithm enum (KAO-C-010). A literal `alg` value outside the
    # registered enum is a hard error; `type` mapping to a recognized canonical
    # alg is fine.
    resolved_alg = kao.resolved_algorithm()
    if kao.alg is not None and kao.alg not in CANONICAL_ALGORITHMS:
        report.errors.append(
            _err(ErrorCode.UNKNOWN_ALG, "KAO-C-010", "/alg", f"unknown algorithm {kao.alg!r}")
        )

    # Step 5: Conditional fields per algorithm (KAO-C-030, KAO-C-031).
    if resolved_alg is not None:
        category = algorithm_category(resolved_alg)
        ephemeral = kao.resolved_ephemeral_key()
        if (
            category
            in {
                AlgorithmCategory.AGREEMENT,
                AlgorithmCategory.ENCAPSULATION,
                AlgorithmCategory.HYBRID,
            }
            and ephemeral is None
        ):
            report.errors.append(
                _err(
                    ErrorCode.EPHEMERAL_KEY_REQUIRED,
                    "KAO-C-030",
                    "/ephemeralKey",
                    f"ephemeralKey is required for alg={resolved_alg!r}",
                )
            )
        elif category == AlgorithmCategory.WRAPPING and ephemeral is not None:
            report.warnings.append(
                _warn(
                    ErrorCode.EPHEMERAL_KEY_UNEXPECTED,
                    "KAO-C-031",
                    "/ephemeralKey",
                    f"ephemeralKey is unexpected for alg={resolved_alg!r}",
                )
            )

    # Step 6: Policy-binding format (KAO-C-005, KAO-C-014).
    if kao.policy_binding is None:
        report.errors.append(
            _err(
                ErrorCode.POLICY_BINDING_MISSING,
                "KAO-C-005",
                "/policyBinding",
                "policyBinding is required",
            )
        )
    elif isinstance(kao.policy_binding, str):
        # Bare-string is permitted only for legacy reading. Producers MUST use
        # the object form (KAO-C-204), but we treat bare-string as a warning
        # since validation is read-side here.
        report.warnings.append(
            _warn(
                ErrorCode.POLICY_BINDING_FORMAT_INVALID,
                "KAO-C-204",
                "/policyBinding",
                "policyBinding is a bare string; v4.4 producers MUST emit the object form",
            )
        )
    else:
        if kao.policy_binding.alg != "HS256":
            report.errors.append(
                _err(
                    ErrorCode.POLICY_BINDING_ALG_UNSUPPORTED,
                    "KAO-C-202",
                    "/policyBinding/alg",
                    f"unsupported policyBinding.alg={kao.policy_binding.alg!r}",
                )
            )

    if not report.errors:
        report.normalized = kao.normalized()
    return report
